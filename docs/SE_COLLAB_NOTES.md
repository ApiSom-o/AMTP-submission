# SE-COLLAB [37]: paper เทียบกับโค้ดของเรา

ตรวจ `baselines/se_collab_sim.py` เทียบกับ paper ต้นฉบับ
S. Fugkeaw, J. Deevijit, "SE-COLLAB: Achieving Fine-Grained and Efficiently Verifiable Searchable Encryption
With Boolean Multi-Keyword Search for Collaborative IIoT Data Sharing", IEEE Access, vol. 13, pp. 126012–126029, 2025.

**สรุป:** โค้ดทำตาม paper ครบทั้ง 8 phase และ Algorithm 1–2 ใช้ library ชุดเดียวกับ paper
(Charm `abenc_bsw07` + PyCryptodome) จำนวน operation หลักตรงกับ Table 4 ของ paper
ส่วนที่ต่างจาก paper มีเหตุผลทุกจุด และติดป้าย `[FIX]` / `[ASSUMPTION]` ไว้ในหัวไฟล์ (ข้อ 1–11)
selftest ผ่าน 18/18

## 1. ส่วนที่ตรงกับ paper

| Phase | ใน paper | ในโค้ด |
|---|---|---|
| 1 Setup | `PK = {g, h=g^β, f, e(g,g)^α}`, `MK = (β, g^α)` | BSW07 ของ Charm (paper พิมพ์ `f = g^β` ผิด ที่ถูกคือ `g^{1/β}`) |
| 2 KeyGen | `D = g^{(α+r)/β}`, `D_j = g^r·H(j)^{r_j}`, `D'_j = g^{r_j}`; คู่คีย์ DO และ Cloud Proxy; `PRE_{A→B} = PK_B^{x_A}` | ตรงทุกตัว |
| 3 Encrypt + Index | `C_i = AES(SymK, D_i)`, `CT_key = CP-ABE(SymK, P)`, `I(w) = PRF(SymK, w)` → `Enc(id)`, BPL, Merkle root ของ index | ตรง (CP-ABE ห่อ SymK แบบ hybrid เพราะ BSW07 เข้ารหัสได้แค่ค่าใน GT) |
| 4 Trapdoor | `3T_E + T_P` ไม่ขึ้นกับจำนวน keyword + signature + ZKP | exp 3 ครั้ง + pairing 1 ครั้ง (ฝั่ง DU เท่านั้น); เวลาคงที่ตาม k_Q เหมือน Fig. 3 |
| 4 Proxy admission (Step 2) | ตรวจ signature + ZKP ไม่มี pairing | ตรวจ signature + ZKP; ไม่มี pairing ฝั่ง proxy (เคยมีการตรวจ `bind` ด้วย pairing ซึ่งไม่อยู่ใน paper ถูกเอาออกแล้ว) |
| 4 Algorithm 1 (PRE) | `C3' = g^ReKey × C3` | ทำตามตัวอักษร |
| 5 Algorithm 2 | ดึง BPL → ConvertToBitwise → Eval AND/OR/NOT → ดึง ciphertext → log | ตรงทีละบรรทัด (comment อ้างเลขบรรทัด) |
| 6 Verify | Merkle path ทีละไฟล์เทียบ root บน chain, ระบุไฟล์ที่ถูกแก้, incremental update | ตรง (selftest `t_tamper_detected`, `t_incremental_merkle`); ค่าเริ่มต้น `--proof-mode paths` = แบบใน paper ส่วน `multi` (multiproof) เป็น optimization ที่ไม่อยู่ใน paper ใช้เมื่อสั่งเท่านั้น |
| 7 Decrypt | CP-ABE → SymK → AES | ตรง |
| 8 Revocation | `RT_k = H(DU ‖ T ‖ Domain)`, Bloom filter แล้วค่อยถาม smart contract, lazy re-encryption, อัปเดตคีย์ของ attribute ที่โดน | ตรง (selftest `t_revocation`) |

## 2. ส่วนที่ต้องตีความเอง (paper ขัดกันเองหรือไม่ได้ระบุ)

| เรื่อง | ปัญหาใน paper | โค้ดทำอย่างไร |
|---|---|---|
| `C3 = PK_DU^r = g^{αr}` (Phase 4) | DU ไม่มี `g^α` (เป็น master key ของ AA) | ใช้ `C3 = PK_DU^r` (`PK_DU = g^{s_u}` ของ DU เอง) |
| C2 กับ ExtractKeyword | ไม่บอกว่า proxy อ่าน W_q จาก C2 ได้อย่างไร | C2 เข้ารหัส query (leaf = PRF token) ด้วยคีย์ `KDF(PK_Cloud^r)` จำนวน exp ยังเป็น 3 |
| ZKP (Phase 4) | สมการไม่สมดุล: δ' ไม่มี W_q, B_q และ V2' ไม่ตรงกับ V2 | Chaum-Pedersen DLEQ NIZK (Fiat-Shamir); signature σ = Schnorr ใน G1 |
| ZKP over (T'q, R) (Phase 6) | ไม่มีรายละเอียด | ลายเซ็น Schnorr ของ proxy บนชุดผลลัพธ์ (2 exp ไม่มี pairing) |
| Lazy re-encryption (Phase 8) | บอกว่าเปลี่ยน SymK ใหม่แต่ C_i ไม่ต้องเข้ารหัสใหม่ (ขัดกันเอง) | หมุนคีย์ที่ห่อ SymK (สร้าง CT_key ใหม่ 1 ครั้ง) + เพิ่มเวอร์ชันของ attribute |
| Attribute key update (Phase 8) | สร้างใหม่เฉพาะ component ของ attribute ที่โดน | สร้างคีย์ใหม่ทั้งชุดให้ user ที่ถือ attribute นั้น (ไม่กระทบ Exp. 1–2) |
| Multi-authority | DU รวมคีย์จากหลาย AA สร้าง trapdoor เดียว | BSW07 ผูก ciphertext กับ AA ตัวเดียว → DO 1 ราย ผูก AA 1 ตัว; DU ถือคีย์หลาย AA ได้ |
| Blockchain | Ganache + Solidity + Web3.py | ledger จำลองแบบ hash-chained ใน Python |
| Pairing group | ไม่ระบุ | Charm SS512 |
| N ใหญ่ | ไม่ได้ทดลองเกิน 10,000 ไฟล์ | keyword ที่ df < N/64 เก็บเป็น posting แล้วแปลงเป็น BPL ตอน query (ConvertToBitwise) |
| ต้นทุน verify (Table 4) | `E + P_e + f_ct·H` แต่ไม่อธิบายว่า "ZKP over (T'q, R)" ทำอะไร | Merkle + Schnorr (2E) ไม่เติม pairing ที่ไม่มีหน้าที่ → verify ที่ implement เป็น lower bound ของ Table 4 (ต้องเขียนหมายเหตุใน paper AMTP) |
| Keyword หลายคำ | ไม่มี (keyword เป็นคำเดี่ยว) | คำที่ติดกันใน query โดยไม่มี operator คั่น = keyword เดียว (dataset-v3 เป็นวลี RAKE) |

## 3. เรื่องที่สำคัญกับ paper AMTP

### 3.1 SE-COLLAB ตรวจไม่เจอการตัดผลลัพธ์ทิ้ง
Sec. V-B ของ SE-COLLAB อ้างว่า DU ตรวจได้ว่า "(i) no valid result is omitted" แต่กลไกใน Phase 6
ตรวจแค่ Merkle path ของ ciphertext ที่ส่งมา และไม่ได้ใช้ index root ตอนตรวจ ถ้า server ตัดผลลัพธ์ทิ้ง
DU จะไม่รู้ โค้ดทำตามกลไกจริง ผลจึงเป็นแบบนั้น (selftest `t_omission_not_detected` และ demo แสดงให้เห็น)
นี่เป็นจุดที่ AMTP ปิดได้ด้วย PAPC + `b_comp` ใช้เป็นข้อโต้แย้งใน paper ได้

### 3.2 ต้นทุนใน Table IV ของ AMTP
Table IV เขียนต้นทุน verification ของ SE-COLLAB เป็น `T_E + T_P + t_leaf T_H` ตาม paper ต้นฉบับ
แต่ที่ implement จริงคือ `2T_E + t_leaf T_H` (ไม่มี pairing เพราะ "ZKP over (T'q, R)" ไม่มีรายละเอียด)
ควรแก้ตารางให้ตรง หรือเขียนหมายเหตุไว้ เช่น "Table 4 of [37] lists E + P_e + f_ct·H for verification but does
not specify the result ZKP; our implementation uses a Schnorr proof (2E), so its verification cost is a lower bound."

### 3.2.1 การแก้ให้ตรง paper (ต้องรัน SE-COLLAB ใหม่ทุก suite)
- เอาการตรวจ `bind` ด้วย pairing ฝั่ง proxy ออก (paper ไม่มี) → `server_total` ลดลง
- ค่าเริ่มต้น `--proof-mode` เปลี่ยนจาก `multi` เป็น `paths` (ตาม Phase 6) → verify ช้าลงและ proof ใหญ่ขึ้นเมื่อผลลัพธ์มาก
- ผลที่วัดก่อนการแก้นี้ (multiproof, มี pairing ฝั่ง proxy) ใช้ไม่ได้แล้ว
- ช่อง completeness ของ SE-COLLAB ในตาราง AMTP: เขียนว่า "ตาม implementation ของ Phase 6" ไม่ใช่ "paper ไม่รองรับ"
  (Section V-B ของ [37] อ้างว่าตรวจได้ แต่กลไก Phase 6 ไม่ตรวจ)

### 3.3 ตัวเลขต้องบอกให้ชัดว่าวัดช่วงไหน
ผลบน dataset-v3, k_Q = 4, query แบบ AND (median ของ 30 รอบ, ms, เครื่องทดสอบ):

| N | trapdoor | query_gen (รวม sig + ZKP) | admission (proxy ตรวจ sig + ZKP + pairing) | transform (PRE) | **search_core** | proof_gen | server_total | merkle_verify | verify_total | end_to_end |
|---|---|---|---|---|---|---|---|---|---|---|
| 10,000 | 1.72 | 2.66 | 2.79 | 0.67 | **0.04** | 0.19 | 3.71 | 0.008 | 0.67 | 7.04 |
| 200,000 | 1.89 | 2.92 | 3.06 | 0.72 | **0.24** | 0.22 | 4.24 | 0.011 | 0.73 | 7.88 |

- Fig. 4/5 ของ paper ต้นฉบับวัดแค่การค้นหา (< 0.61 ms) เทียบได้กับ `search_core` ของเรา (0.04–0.24 ms)
- `server_total` ที่ใช้ในกราฟ `secollab_exp1_*` รวมการตรวจรับ query ฝั่ง proxy (~2.9 ms) ไว้ด้วย
  SE-COLLAB ในกราฟของเราจึงดูช้ากว่าตัวเลขใน paper ของเขาเอง ตอนเขียน paper ต้องบอกว่าเทียบแบบ
  end-to-end รวมการตรวจรับ query
- Trapdoor: เรา 1.7–1.9 ms, paper ~6.3 ms (Python 3.8 + Xeon E-2336); ทั้งคู่คงที่ตาม k_Q
- Merkle verify 5–40 ผลลัพธ์ (`python3 se_collab_sim.py paper`): เรา 0.05–0.39 ms, paper 0.093–0.446 ms

## 4. ต่างจากการทดลองใน paper ต้นฉบับ
- Paper ทดลองที่ 10–40 ไฟล์ (Fig. 2) และ 25–200 keyword ต่อ query (Fig. 3–4) ส่วนเราทดลองตาม AMTP
  Exp. 1–2 (N = 10k–200k, k_Q = 1–16) ส่วน `paper` ใน `se_collab_sim.py` จำลองค่าตั้งของ Fig. 2–6 ไว้ใช้ sanity check
- Paper วัดบน Python 3.8, Intel Xeon E-2336, Ubuntu 22.04; ของเราวัดบน macOS + Python 3.12
  (ตัวเลขยังไม่ใช่ผลสุดท้าย ต้องรันซ้ำบนเครื่องที่จะรายงานใน paper)
