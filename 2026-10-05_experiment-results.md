# Kết quả thực nghiệm FirmAgent/FITS

> Ngày tổng hợp: 05/10/2026  
> Nguồn số liệu: bảng kết quả thực nghiệm được cung cấp.  
> Phạm vi: so sánh các cấu hình firmware, FITS và mô hình LLM theo số alert/finding, replay hoặc PoC, và kết luận xác minh.

## Tóm tắt

Kết quả gần với paper nhất là **TEW800 C7 (FITS source + BPDA)**: phát hiện 23 endpoint/path-level findings và các path này hội tụ về 1 root cause. FITS ở chế độ metadata-only gần như không thay đổi coverage; việc mở rộng source trong C7 cho hiệu quả rõ ràng hơn. Các số liệu `23 ↔ 43` và `11 ↔ 43` phụ thuộc quy ước đếm vì có các path chồng lấp.

## Bảng tổng hợp

| Firmware / lần chạy | Paper | Kết quả LLM | Replay / PoC | Kết luận |
|---|---:|---|---|---|
| TEW800, lần cũ | 25 alert / 23 vuln | 11 alert, 1 vuln | Chưa replay đầy đủ | Đã supersede |
| TEW800 C4, runtime + BPDA | 25 / 23 | 33 alert, 27 hypothesis | 25 flow an toàn, chưa test overrun | 0 vuln xác minh |
| TEW800 C5, FITS metadata-only | 25 / 23 | 25 alert, 19 hypothesis | 17 source-to-sink, không overrun | 0 vuln xác minh |
| TEW800 C7, FITS source + BPDA | 25 / 23 | 38 alert pairs, 27 hypothesis | 23/23 destination overrun | 23 endpoint/path findings, 1 root cause |
| TEW800 full E2E, Gemini 3.6 | 25 / 23 | 41 hypothesis | 20 pair, 120/120 overrun | 20 path observations, 1 root cause |
| TEW800 full E2E, GPT-5.5 | 25 / 23 | 45 validated, 3 alert-only | 11 LLM paths; 43 deterministic pairs overrun | 11 hoặc 43 path tùy quy ước, 1 root cause |
| TEW632BRPA1 | 10 / 8 | 76 dataflow alert, 32 hypothesis | Sink 0/32, overrun 0/32 | 0 vuln xác minh |
| Tenda W6-S | 14 / 12 | 107 finding rows, raw LLM verified 0 | 6 endpoint findings | 6 endpoint findings, 3 root-cause families |
| Netgear DC112A, graph preflight | Chưa chốt | LLM chưa chạy | 2.751 bounded paths | Chưa có kết quả vuln |
| Netgear DC112A, full GPT-5.5 | Chưa chốt | 42 alert, 11 hypothesis | Không reach sink, overrun 0 | 0 vuln xác minh |

## Diễn giải kết quả

### TEW800

- Cấu hình cũ đã được thay thế vì chưa replay đầy đủ và chỉ cho 11 alert, 1 vuln.
- C4 tạo 33 alert và 27 giả thuyết, nhưng 25 flow replay đều an toàn; chưa có kiểm tra overrun đầy đủ.
- C5 với FITS metadata-only cho 25 alert và 19 giả thuyết. Có 17 source-to-sink path nhưng không path nào overrun.
- C7 bổ sung FITS source expansion cùng BPDA: 38 alert pairs, 27 giả thuyết và 23/23 destination overrun. Đây là cấu hình có kết quả sát paper nhất ở cấp endpoint/path, dù 23 finding cuối cùng quy về cùng một root cause.
- Chạy full E2E với Gemini 3.6 cho 20 pair và 120/120 overrun; với GPT-5.5 cho 45 validated và 43 deterministic pairs overrun. Hai cách đếm ở GPT-5.5 có thể lần lượt cho 11 LLM paths hoặc 43 deterministic paths.

### Các firmware khác

- **TEW632BRPA1:** 76 dataflow alert và 32 hypothesis, nhưng không sink nào trong 32 hypothesis được reach; chưa xác minh được vuln.
- **Tenda W6-S:** 6 endpoint findings, được nhóm thành 3 root-cause families.
- **Netgear DC112A:** graph preflight đã tạo 2.751 bounded paths. Ở full GPT-5.5, không hypothesis nào reach sink và overrun bằng 0; chưa có vuln được xác minh.

## Evidence → finding → path

| Evidence | Finding | Path / phạm vi |
|---|---|---|
| Bảng số liệu thực nghiệm được cung cấp | C7 là cấu hình có độ bao phủ và kết quả replay nổi bật nhất trên TEW800 | 23/23 destination-overrun paths, quy về 1 root cause |
| Kết quả C5 (metadata-only) | Metadata-only không cải thiện coverage đáng kể | 17 source-to-sink paths, không overrun |
| Kết quả TEW632BRPA1 và Netgear DC112A full GPT-5.5 | Alert/hypothesis không đồng nghĩa vuln đã xác minh | Không reach sink hoặc overrun bằng 0 |
| Kết quả Tenda W6-S | Finding theo endpoint có thể hội tụ về ít nguyên nhân gốc hơn | 6 endpoint findings, 3 root-cause families |

## Kết luận

1. Kết quả tốt nhất và gần paper nhất là **TEW800 C7**: 23 endpoint/path-level findings, nhưng các path này hội tụ vào **1 root cause**.
2. **FITS metadata-only** gần như không làm thay đổi coverage; **FITS source expansion** trong C7 có tác dụng rõ ràng.
3. Không nên so sánh trực tiếp các số `23`, `43`, `11` nếu chưa thống nhất đơn vị đếm: endpoint/path, LLM path hay deterministic pair; các path có thể overlap.
4. Một alert hoặc hypothesis chỉ nên được coi là finding sau khi có bằng chứng reach sink/overrun hoặc replay/PoC tương ứng.
