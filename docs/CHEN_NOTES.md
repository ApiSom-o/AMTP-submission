# Chen et al. [40]: paper เทียบกับโค้ดของเรา

ตรวจ `baselines/chen_et_al_sim.py` เทียบกับ paper ต้นฉบับ
L. Chen, Y. Wu, H. Zhang, J. Weng, Z. Liu, "Verifiable Multi-User Dynamic Searchable Symmetric Encryption With
Forward and Backward Privacy Feasible for Cloud Storage" (VM-DSSE-FB), IEEE TIFS, vol. 21, pp. 3797–3811, 2026.

**สรุป:** โค้ดทำตาม paper ครบทั้ง Algorithm 1–5 (Setup, Share, Update, Search, Verify) comment ในโค้ดอ้าง
เลขบรรทัดของ algorithm ไว้ (`[Alg.4 L20]`) จุดที่ paper เขียนผิดหรือไม่ได้ระบุติดป้าย `[FIX]` / `[ASSUMPTION]`
ไว้ในหัวไฟล์ (ข้อ 1–9) `selftest` ผ่าน 13/13 รวมกรณี CS ซ่อนผลลัพธ์, ข้าม entry เก่า และปลอม proof

## 1. ส่วนที่ตรงกับ paper

| ส่วน | ใน paper | ในโค้ด |
|---|---|---|
| Bitmap + homomorphic addition (Sec. II-A, II-F) | `Enc(sk, m) = (sk + m) mod 2^γ`; ลบเอกสาร = บวก `−2^id mod n` (Fig. 1) | ตรง (selftest `t_fig1`) |
| Alg. 1 Setup | `n = 2^γ`, CT / EDB ว่าง | ตรง |
| Alg. 2 Share / Alg. 3 Update | state chain `UT_c = H1(K_w, ST_c)`, `C_ST = H2(K_w, ST_c) ⊕ ST_{c−1}`, `e_c = Enc(H3(K'_w, c), bs)`, `vt = F1(w‖c−1) ⊕ F1(w‖c) ⊕ F1(id)`, คิวต่อผู้ใช้ (CntDiffs) | ตรงทีละบรรทัด; update สร้าง entry ให้ทุกผู้ใช้ใน AccessList → `O(N_u·m)` |
| Alg. 4 Search | DU sync คิว → token `(K_w, ST_c, c)` → CS เดิน chain, `Add` ciphertext, XOR proof, ลบ entry เก่าแล้วเก็บผลรวม → DU ถอดแล้ว AND | ตรง (selftest `t_aggregation`, `t_long_chain`) |
| Alg. 5 Verify | `proof' = F1(w‖−1) ⊕ F1(w‖c) ⊕ ⨁ F1(id)` เทียบกับ proof ของ CS | ตรง (selftest `t_reject_missing`, `t_reject_dropped`, `t_reject_forged`) |
| Forward privacy | update ใหม่ได้ `UT` ที่ token เก่าคำนวณไม่ได้ | ตรง (selftest `t_forward`) |
| Multi-user | DU คนละคนเห็นเฉพาะเอกสารที่แชร์ให้ | ตรง (selftest `t_multi_user`) |
| Query | multi-keyword แบบ AND เท่านั้น (Alg. 4 L42) | OR / nested เขียนเป็นแถว `status=N/A` |

## 2. ส่วนที่ paper ผิดหรือไม่ได้ระบุ (ข้อ 1–9 ในหัวไฟล์)

| เรื่อง | ปัญหาใน paper | โค้ดทำอย่างไร |
|---|---|---|
| `K_u` (Alg. 2 L2) | สุ่มใหม่ทุกครั้งที่ Share → ข้อมูลที่แชร์ไปก่อนหน้าค้นไม่เจอ | `[FIX]` สุ่มเฉพาะครั้งแรกของผู้ใช้ |
| CntDiffs (Alg. 2 L12) | เก็บแค่ `Enc(w, c)` แต่ Alg. 4 L4 ต้องใช้ `ST_c` | `[FIX]` เข้ารหัส `(w, c, ST_c)` |
| Alg. 5 | `return accept` หลังเช็ค keyword แรก | `[FIX]` เช็คครบทุก keyword ก่อน accept และ reject ถ้า CS ส่ง `(Sum_e, proof)` มาไม่ครบทุก keyword ใน q (เดิม `zip` ตัดส่วนเกินทิ้งเงียบ ๆ ทำให้ CS ตัดผลของ keyword หนึ่งทิ้งแล้วยังผ่าน; selftest `t_reject_dropped_keyword`) |
| ความยาว bitmap γ (Sec. II-A) | เขียน `γ = ⌈log₂ N_max⌉` ซึ่งเก็บ N ไฟล์ไม่ได้ (bitmap ต้องมี 1 บิตต่อไฟล์) | `[ASSUMPTION]` γ = N (+ ที่เผื่อเอกสารใหม่ใน Exp. 3) |
| คีย์ของ F1 | ไม่ระบุ | ใช้ `K'_u` (DU คำนวณ proof ได้ CS ปลอมไม่ได้) |
| Primitive | ไม่ระบุ | HMAC-SHA256/512 (PRF), SHA-256 (H1, H2), SHAKE-256 (H3 ยาว γ บิต), AES-256-GCM, λ = 128 |
| Update | Fig. 1 มีทั้งเพิ่มและลบ แต่ Alg. 3 เขียนแบบเดียว | รองรับทั้ง ADD (`+2^id`) และ DEL (`−2^id mod n`) |
| Share หลายเอกสาร | Share ทีละเอกสาร | ตอนสร้าง index เริ่มต้นรวม bitmap ของ keyword เดียวกันเป็น entry เดียว; Exp. 3 ยัง update ทีละเอกสารตาม paper (`--update-mode per-doc`) |
| ขนาด index ที่ N ใหญ่ | index เต็ม = keyword ไม่ซ้ำ × γ บิต ต่อผู้ใช้ (N = 200k → ~1.29 ล้านคำ → ~32 GB) | `--scope auto`: เกิน 4 GB สร้างเฉพาะ keyword ที่ทดลอง โดย bitmap ของคำนั้นครบทุกเอกสาร เวลาค้น/verify จึงเท่าแบบเต็ม; `cs_storage_bytes` ยังรายงานขนาด index เต็ม (คอลัมน์ `index_scope`) |

## 3. เรื่องที่สำคัญกับ paper AMTP

### 3.1 Chen ตรวจความครบได้ แต่ทุกอย่างโตตาม γ = N
- Proof ของ Chen ครอบคลุมทุกเอกสารที่ match (`⨁ F1(id)`) จึงจับการซ่อนผลลัพธ์ได้ ต่างจาก SE-COLLAB
- แต่ bitmap ยาว N บิต: การถอด bitmap, การเข้ารหัสตอน update และขนาด index โตตาม N ทั้งหมด
  - Exp. 1 (k_Q = 4, AND): end-to-end 0.14 ms ที่ N = 10k → 1.41 ms ที่ 200k
  - Exp. 3: update ต่อเอกสาร 0.23 ms ที่ N = 10k → ~1.0 ms ที่ 200k
  - index เต็ม ~32 GB ที่ N = 200k
- Paper ของ Chen เองยอมรับใน Sec. VII ว่า bitmap ความยาวคงที่เป็นข้อจำกัด และเสนอ "dynamic partition optimization"
  เป็นงานอนาคต ซึ่งตรงกับสิ่งที่ AMTP ทำ ใช้อ้างใน paper ได้

### 3.2 ตัวเลขของเรา (dataset-v3, k_Q = 4, AND, median 30 รอบ, ms, เครื่องทดสอบ)

| N | query_gen | server_total | du_decrypt | verify_total | end_to_end | index_scope |
|---|---|---|---|---|---|---|
| 10,000 | 0.010 | 0.013 | 0.036 | 0.079 | 0.14 | full |
| 200,000 | 0.009 | 0.038 | 0.396 | 0.964 | 1.41 | queried |

`du_decrypt` ของ Chen คือการถอด bitmap ผลลัพธ์ (ส่วนหนึ่งของ Alg. 4) ไม่ใช่การถอดไฟล์ เพราะ Chen คืนแค่ id

### 3.3 Table IV ของ AMTP
ต้นทุนใน Table IV ตรงกับที่ implement: query `O(n_w)·T_PRF`, search `O(n_w·n_u)(T_H + T_A + T_X)`,
verify `O(r_C)(T_PRF + T_X)`, update `O(N_u·m)(T_PRF + T_H + T_Enc)` คอลัมน์ `prf_*`, `hash_*`, `add_*`, `xor_*`
ใน CSV นับจำนวน operation จริงไว้ให้ตรวจกับสูตรได้

## 4. ต่างจากการทดลองใน paper ต้นฉบับ
- Paper ใช้ CAN-intrusion dataset 1,000 ไฟล์ (6,783 keyword) บน Java + JPBC, Intel i7-10700, Windows 10
- ของเราใช้ dataset-v4 (arXiv, 4 domain x 125,000 ไฟล์, κ = 20) บน Python + `cryptography` จึงเทียบตัวเลขกับ paper ตรง ๆ ไม่ได้
  (ตัวเลขในหัวข้อ 3.2 เป็นผลเก่าบน dataset-v3 ไว้ดูแนวโน้มเท่านั้น)
- ตัวเลขยังไม่ใช่ผลสุดท้าย ต้องรันซ้ำบนเครื่องที่จะรายงานใน paper
