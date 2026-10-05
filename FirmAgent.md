FirmAgent 

```
                    Firmware
                       │
                       ▼
              ┌─────────────────┐
              │ Firmware        │
              │ Rehosting       │
              └────────┬────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │      PRE-FUZZING ANALYSIS    │
        │                              │
        │  1. Service Handler Detection│
        │  2. Keyword Dictionary       │
        │  3. Sink Extraction          │
        │  4. Sink Scope + Distance    │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │ FUZZING-DRIVEN INFORMATION   │
        │        COLLECTION            │
        │                              │
        │ Dictionary Mutation          │
        │ Distance-Guided Mutation     │
        │ QEMU Runtime Monitoring      │
        │ Memory Taint Detection       │
        │ Indirect Call Resolution     │
        └──────────────┬───────────────┘
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
         Csource            Dynamic Call Graph
             │                   │
             └─────────┬─────────┘
                       ▼
               Potential Paths
               Csource → Sink
                       │
                       ▼
        ┌──────────────────────────────┐
        │       TAINT-TO-POC AGENT     │
        │                              │
        │ Decompiled-code refinement  │
        │          ↓                   │
        │ Taint Propagation Agent      │
        │          ↓                   │
        │ Alert Verification           │
        │          ↓                   │
        │ PoC Generation Agent         │
        └──────────────┬───────────────┘
                       │
                       ▼
                  Concrete PoC
                       │
                       ▼
              Vulnerability Validation
```

# 1. Firmware rehosting

Đưa service vào môi trường chạy được. Trong implementation của bài

# 2. Pre-Fuzzing

Phân tích binary phục vụ fuzzing:
+ Service Handler Detection
+ Keyword Dictionary Analysis
+ Sink Scope and Distance Calculation

## 2.1. Service Handler detection

Tìm các service handler/request handler

```
/apply.cgi
/goform/login
/NTPSyncWithHost.cgi
/api/config
...
```

Một URL thường ánh xạ tới một backend handler

## 2.2. Keyword Dictionary Analysis

Cần biết parameter nào có thể nhận dữ liệu từ user

```
POST /apply.cgi

username=abc
password=xyz
deviceName=router
host=1.2.3.4
```

FirmAgent xây một keyword dictionary:

```
K = {
    "username",
    "password",
    "deviceName",
    "host",
    ...
}
```

Paper bắt đầu thu từ network traffic khi tương tác với firmware đã rehost. Sau đó binary được phân tích để tìm các function xử lí keyword để mở rộng dictionary

VD:

```
websGetVar(req, "deviceName", ...);
```

thì _deviceName_ sẽ trở thành một fuzzing keyword

Qua 2 phần này sẽ biết gửi request vào đâu và mutate field nào

## 2.3. Sink Identification

Tìm các sink

```
system()
popen()
exec*()

strcpy()
sprintf()
memcpy()
...
```

VD

```
input = websGetVar(...);

sprintf(buf, "ping %s", input);

system(buf);
```

thì

```
websGetVar(...)   → source side
system(...)       → sink
```

## 2.4. Sink scope

Từ mỗi sink, làm backward để xác định những block nào có khả năng dẫn tới sink. Tập này sẽ trở thành sink scope. Mục tiêu là làm giảm overhead của runtime, thay vì monitor toàn bộ. Chỉ tập trung dynamic taint detection trên các region có thể dẫn đến sink

## 2.5 Distance Calculation

Tính khoảng cách trên CFG. Khoảng cách sau này dùng cho distance guilded fuzzing

# 3. Fuzzing-driven information collection

## 3.1. Directed Fuzzing

Bắt đầu fuzz

Logic :

```
for handler in H:

    request.URI = handler

    for keyword in K:

        inject taint into keyword

        score = distance_to_sink()

        mutated_input =
            guided_mutation(request, score)

        execute(mutated_input)
```

Mục tiêu là thu thập bằng chứng runtime cho LLM analysis

# 3.2. QEMU Runtime monitoring

Dùng Qemu để thu được :

+ Csource
+ indirect call target

## 3.3. Memory Taint Detection 

FirmAgent quan sát runtime, nếu input thực sự làm một memory thành tainted thì cái lệnh đó được ghi nhận là Csource

Kiểm tra memory state sau cái lệnh để phát hiện transition untainted -> tainted và ghi lại địa chỉ lệnh tương ứng để giảm source false positive

## 3.4. Indirect Call Resolution

Dựng call graph đầy đủ. Từ runtime, ta sẽ bổ sung thêm những cạnh còn thiếu vào trong static call graph

# 4. Potential Vulnerability Path Construction

Có Csource -> Call graph + sink thì có :

```
Csource
   │
   ▼
function A
   │
   ▼
function B
   │
   ▼
function C
   │
   ▼
Sink
```

Tuy nhiên mới chỉ là một potential vulnerability path chứ chưa phải vulnerability đã xác nhận. Chỉ chứng minh rằng có 1 path truyền tới sink chứ không chứng minh rằng taint có thực sự đi hết path

# 5. Taint to PoC Agent

Từ Potential path + Decompiler output + csource + sink + Reachable fuzzing testcase. Các path thì giao cho taint propagation agent, còn alert thì giao cho PoC generation agent

## 5.1. Decompiled code refinement

Dùng IDA decompiler

Ngon nhưng IDA có thể bỏ mất return value, argument, control dependency

Dùng 1 LLM refinement step trước khi taint

## 5.2. Taint Propagation Agent

LLM sẽ được hỏi xem data từ Csource có thực sự lan truyền tới sink không. Prompt cơ bản là sẽ chứa:: Decompiled Code, Sources, Sink. Xác định xem taint có lan truyền từ source tới sink. 

## 5.3. LLM Alert

Nếu LLM kết luận taint chạm tới sink và tiềm ẩn khả năng nguy hiểm thì sẽ sinh ra Alert(source, sink)

VD : __('alert', 0xA26C, 0xCC80)__

## 5.4. Alert verification

FirmAgent biết là LLM taint analysis vẫn có thể sai nên thêm 1 alert verification module sử dụng few-shot prompting để kiểm tra alert lần nữa

```
Taint Agent
    │
    ▼
Potential Alert
    │
    ▼
Alert Verification
    │
 ┌──┴──┐
 ▼     ▼
keep  reject
```

## 5.5. Constraint Extraction

LLM cũng lấy các ràng buộc để reach sink

VD:

```
if (strcmp(mode, "admin") == 0)
    ...
```

Thì LLM cần hiểu rằng mode == "admin", thì input mới thỏa mãn ràng buộc đầu vào, giúp sinh PoC

## 5.6. Reachable testcase từ Fuzzing

Ở fuzzing, FA đã giữ lại request, testcase thực sự chạy tới vùng có Csource

vd:


```
POST /NTPSyncWithHost.cgi HTTP/1.1
Host: 192.168.1.1

time=123
```

Thay vì tự tạo một request HTTP từ đầu, rồi chỉ yêu cầu chỉnh phần cần thiết

# 6. PoC Generation Agent

Agent lấy : reachable testcase + source information + sink information + path constraints + sanitization conditions để sửa input

vd ban đầu là time=123 thì LLM có thể suy luận ra cần dạng là time=<1_cai_gi_do> để tạo PoC candidate

# 7. Validation

Chạy lại PoC trên firmware 

```
PoC
 │
 ▼
Rehosted target
 │
 ▼
Does vulnerable effect happen?
```

Nếu có bằng chứng thực thi phù hợp thì finding được xem là được xác nhận mạnh hơn nhiều so với static alert thuần túy và chia PoC thành :
+ E-PoC : chạy trực tiếp, không chỉnh
+ H-PoC : Chỉnh nhẹ bằng tay
+ F-PoC: không chứng minh được vuln

Kết quả 167 E-PoC, 15 H-PoC, 18 H-PoC

# 8. Vấn đề của FirmAgent mà có thể đả động

## 8.1. Fuzzing chưa phủ hết source

Phần Directed fuzzing, paper bảo source identification chỉ phủ 94.2%. Các source nằm ở điều kiện phức tạp hoặc sâu thì bị bỏ sót

## 8.2. Directed fuzzing phụ thuộc khả năng reach path sâu

Tắt direct strategy, hệ thống mất 6 vuln vì một số deep path source không được reach

## 8.3. Indirect-call recovery 

Ở phần call graph, các indirect target chưa từng được execute vẫn không được recover

## 8.4. IDA decompilation không chính xác

Có thể mất tham số function, return assignment hoặc sai data flow structure làm LLM suy luận sai

## 8.5. LLM taint reasoning sinh false positive 

Ở phần taint propagation agent, hiểu sai indirect dêpndency coi dữ liệu từ system file là attacker controlled source

## 8.6. Buffer overflow reasoning chưa tốt

LLM verification, llm đôi khi không hiểu đúng quan hệ giữa input size và buffer size nên không thể xảy ra thực thế. Nên đây là nguồn FP quan trọng

## 8.7. PoC generation chưa hoàn toàn tự động

Vẫn cần trường hợp sửa thủ công

## 8.8. Runtime cao hơn static 

1 giờ fuzzing cao hơn static 3-8p

