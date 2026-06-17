"""
build_kb.py — 多粒度向量索引版（每個 TTP 4 個向量入口）
=====================================================================
每個 TTP 拆成 4 個獨立向量：
  ID="T1003.003#L1"  → ATT&CK 技術描述
  ID="T1003.003#L2"  → Procedure Examples（含工具上下文）
  ID="T1003.003#L3"  → 工具/惡意軟體名稱
  ID="T1003.003#L4"  → Atomic Red Team 真實攻擊指令

查詢時取最近的向量，用 # 前面的 T-ID 作為實際命中結果。
這樣工具名稱查詢可以直接命中 L3/L4，而不被長篇 L1 描述稀釋。
"""
import json, os, re
import chromadb
from sentence_transformers import SentenceTransformer

JSON_FILE       = "full_mitre_data.json"
ATOMIC_FILE     = "atomic_red_team_windows.json"
DB_PATH         = "./my_soc_vectordb"
COLLECTION_NAME = "mitre_rules"

TOOL_EXTRACT_PATTERNS = [
    r'\b([A-Za-z][A-Za-z0-9_\-]{2,}\.exe)\b',
    r'\b([A-Za-z][A-Za-z0-9_\-]{3,})\s+(?:/|-)',
    r'\bInvoke-([A-Za-z][A-Za-z0-9]+)\b',
    r'\b([A-Za-z][a-z]+[A-Z][A-Za-z]+\.exe)\b',
]
TOOL_STOPWORDS = {
    "the","this","that","with","from","have","been","used","using",
    "they","their","other","also","such","some","into","over",
    "windows","system","local","remote","domain","active","directory",
    "network","service","process","memory","file","data","access",
    "attack","target","victim","threat","actor","group",
}

MANUAL_ALIASES = {
    "T1003.001": ["comsvcs minidump lsass", "rundll32 comsvcs",
                  "outflank-dumpert", "nanodump"],
    "T1003.003": ["ntdsutil ifm", "ntdsutil activate instance",
                  "vssadmin shadow ntds"],
    "T1558.003": ["rubeus asktgt", "rubeus asktgs", "rubeus kerberoast"],
    "T1003.002": ["esentutl sam", "esentutl vss sam"],
    "T1003.004": ["reg save hklm security", "lsa secrets"],
}


def extract_tool_names(text):
    found = set()
    for pattern in TOOL_EXTRACT_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            name = m.group(1).lower().replace('.exe','')
            if len(name) > 3 and name not in TOOL_STOPWORDS:
                found.add(name)
    return sorted(found)[:20]


def load_atomic_red_team():
    if not os.path.exists(ATOMIC_FILE):
        print(f"⚠️  找不到 {ATOMIC_FILE}，跳過 Layer 4")
        return {}
    with open(ATOMIC_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(f"📚 載入 Atomic Red Team：{len(data)} 個 TTP")
    return data


def build_knowledge_base():
    print("🚀 MITRE ATT&CK 知識庫建置（多粒度向量索引版）\n")

    if not os.path.exists(JSON_FILE):
        print(f"❌ 找不到 {JSON_FILE}")
        return

    atomic_data = load_atomic_red_team()

    print(f"\n📂 解析 {JSON_FILE}...")
    with open(JSON_FILE, 'r', encoding='utf-8') as f:
        stix_data = json.load(f)
    objects = stix_data.get("objects", [])

    # STIX ID 對照
    stix_to_tid = {}
    for obj in objects:
        if (obj.get("type") == "attack-pattern" and not obj.get("revoked")
                and not obj.get("x_mitre_deprecated")):
            for ext in obj.get("external_references", []):
                if ext.get("source_name") == "mitre-attack":
                    tid = ext.get("external_id", "")
                    if tid:
                        stix_to_tid[obj["id"]] = tid

    # tool/malware 物件
    stix_tool_names = {}
    for obj in objects:
        if obj.get("type") in ("tool", "malware"):
            names = [obj.get("name", "").lower()]
            names += [a.lower() for a in obj.get("aliases", [])]
            stix_tool_names[obj["id"]] = [n for n in names if n and len(n) > 2]

    # uses 關係
    tid_to_procedures = {}
    tid_to_tools = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        tid = stix_to_tid.get(obj.get("target_ref", ""), "")
        if not tid:
            continue
        desc = obj.get("description", "").strip()
        if desc:
            tid_to_procedures.setdefault(tid, [])
            if len(tid_to_procedures[tid]) < 5:
                clean = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', desc)
                clean = re.sub(r'<[^>]+>', '', clean)
                clean = re.sub(r'\s+', ' ', clean).strip()
                tid_to_procedures[tid].append(clean[:250])
            extracted = extract_tool_names(desc)
            if extracted:
                tid_to_tools.setdefault(tid, set()).update(extracted)
        if obj.get("source_ref", "") in stix_tool_names:
            tid_to_tools.setdefault(tid, set()).update(stix_tool_names[obj["source_ref"]])

    print(f"   → Procedure: {len(tid_to_procedures)} TTP")
    print(f"   → 工具名稱: {len(tid_to_tools)} TTP")
    print(f"   → Atomic: {len(atomic_data)} TTP")

    # 多粒度組合：每個 TTP 拆成 4 個獨立向量
    layered_kb = []   # list of (id, text)

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        tid = stix_to_tid.get(obj["id"], "")
        if not tid:
            continue

        name = obj.get("name", "")
        desc_full = obj.get("description", "")
        paragraphs = [p.strip() for p in desc_full.split('\n') if p.strip()]

        # Layer 1：技術描述（獨立向量）
        layer1 = f"{name}: " + " ".join(paragraphs[:2])[:400]
        layered_kb.append((f"{tid}#L1", layer1))

        # Layer 2：Procedure（獨立向量）
        if tid in tid_to_procedures and tid_to_procedures[tid]:
            layer2 = f"{name} attack procedures: " + " | ".join(tid_to_procedures[tid])
            layered_kb.append((f"{tid}#L2", layer2))

        # Layer 3：工具名稱（獨立向量，短文字更聚焦）
        all_tools = set()
        if tid in tid_to_tools:
            all_tools.update(tid_to_tools[tid])
        if tid in MANUAL_ALIASES:
            all_tools.update(MANUAL_ALIASES[tid])
        if all_tools:
            tools = sorted(all_tools)[:20]
            layer3 = f"{name} tools: " + " ".join(tools)
            layered_kb.append((f"{tid}#L3", layer3))

        # Layer 4：Atomic 攻擊指令（獨立向量）
        if tid in atomic_data:
            cmds = []
            for atomic in atomic_data[tid][:8]:
                cmd = atomic.get("command", "").strip()
                cmd = re.sub(r'#\{[^}]+\}', '', cmd)
                cmd = re.sub(r'\s+', ' ', cmd).strip()
                if cmd and len(cmd) > 5:
                    cmds.append(cmd[:150])
            if cmds:
                layer4 = f"{name} commands: " + " | ".join(cmds)
                layered_kb.append((f"{tid}#L4", layer4))

    print(f"\n✔️ 多粒度索引：{len(layered_kb)} 個向量入口")

    # 向量化
    print("\n⏳ 載入嵌入模型...")
    embedder = SentenceTransformer('all-MiniLM-L6-v2')

    print(f"🗄️ 初始化 ChromaDB @ {DB_PATH}")
    client = chromadb.PersistentClient(path=DB_PATH)
    try:
        client.delete_collection(name=COLLECTION_NAME)
        print("   🧹 清除舊版")
    except Exception:
        pass

    collection = client.create_collection(name=COLLECTION_NAME)

    ids   = [x[0] for x in layered_kb]
    texts = [x[1] for x in layered_kb]

    print(f"🧠 向量化 {len(ids)} 個入口...")
    embeddings = embedder.encode(texts, show_progress_bar=True).tolist()

    print("💾 寫入 ChromaDB...")
    batch = 200
    for i in range(0, len(ids), batch):
        collection.add(
            ids=ids[i:i+batch],
            embeddings=embeddings[i:i+batch],
            documents=texts[i:i+batch]
        )

    print(f"\n{'='*60}")
    print(f"🎉 多粒度知識庫建置完成！共 {len(ids)} 個向量入口")
    print(f"   每個 TTP 最多 4 個獨立向量入口（L1/L2/L3/L4）")
    print(f"   查詢時取 # 前面的 T-ID 作為命中結果")
    print('='*60)


if __name__ == "__main__":
    build_knowledge_base()
