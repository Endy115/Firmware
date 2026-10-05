BPDA là phương pháp phân tích đường dẫn và dữ liệu 2 chiều, giải quyết vấn đề false negative do bỏ sót nonstandard sink và false positive do phải phân tích quả nhiều source-> sink path không thực sự phụ thuộc vào input của attacker. Framework gồm 3 thành phần chính là SrcFinder, SinkLens và Bidirectional Taint Analysis, sau đó có thêm bước sinh PoC

# 1. BPDA

```
                    Firmware
                       │
                       ▼
                Firmware unpack
                    binwalk
                       │
                       ▼
             ┌──────────────────┐
             │    SrcFinder     │
             │  Find sources    │
             └────────┬─────────┘
                      │
                      │ sources
                      ▼
             ┌──────────────────┐
             │     SinkLens     │
             │    Find sinks    │
             │                  │
             │ Standard sinks   │
             │       +          │
             │ Nonstandard sinks│
             └────────┬─────────┘
                      │
                      ▼
             Source → Sink pairs
                      │
                      ▼
              Call-path generation
                      │
          cross-boundary + integration
                      │
                      ▼
            Backward data-flow
                    tracking
                      │
              Is sink argument
            dependent on source?
                  /       \
                NO         YES
                │           │
              DROP         KEEP
                            │
                            ▼
                  Forward taint
                     analysis
                            │
                  type inference
                  sanitization
                            │
                            ▼
                   Vulnerable path
                            │
                            ▼
                    PoC generation
```

# 2. SrcFinder

Src sẽ giải quyết vấn đề dữ liệu do attacker kiểm soát đi vào firmware chỗ nào. Bài toán xác định taint source. Chia source thành nhiều nhóm. Các source :

```
Front-end receiver
    websGetVar()
    jsonObjectGetString()
        ↓

Environment / persistent storage
    getenv()
    nvram_get()
        ↓

File input
    fgets()
    read()
        ↓

Network input
    recv()
    recvfrom()
```

BPDA muốn tập source rộng hơn. Dùng ở giai đoạn sinh PoC

Ý tưởng của BPDA:

```
Web front-end
     │
     │ keyword
     ▼
"username"
     │
     │ string reference
     ▼
Binary
     │
     ▼
function handling "username"
     │
     ▼
candidate input function
```

Nghĩa là giả sử trên code của frontend có : 
```html
<input name="username">
```
thì trong binary sẽ có : __get_param("username");__

nên chuỗi username sẽ tạo cầu nối front và back. 

Các chuỗi shared-string này lấy từ IDAPython hoặc từ SaTC

__Điểm mạnh__: phủ source rộng hơn so với việc chỉ dùng libc source, phù hợp firmware web

__Điểm yếu__: Chưa chứng minh được shared-string một attacker-controlled, vẫn có khả năng FP/FN source identification

# 3. Sinklens

Các hệ thống truyền thống thường định nghĩa sink bằng 1 danh sách:

```
strcpy
strncpy
memcpy
sprintf
system
...
```

Nhưng firmware có thể tự định nghĩa kiểu:

```c++
void my_copy(char *dst, char *src) {
    while (*src) {
        *dst++ = *src++;
    }
}
```

Không có strcpy nhưng nghĩa của hành vi là gần như nhau : src memory -> load -> loop -> store -> dst memory. Nếu mà trường hợp buffer dst không đủ lớn thì đây là 1 lỗi, nếu bỏ qua thì sẽ là nguồn false negative quan trọng

Cách để nó nhận diện các hàm kiểu kia là nó sẽ kết hợp Loop structure + memory access + parameter usage + mối quan hệ giữa src/dst/length để nhận diện các hành vi kiểu copy như trên. Việc phân tích quan hệ giữa tham số hàm với cấu trúc vòng lặp sẽ giúp phân biệt hàm copy với các hàm vô tình có cấu trúc vòng lặp

Dùng IDAPython để tìm loop structure, networkx để graph processing và PyVEX/PyVEX IR cho biểu diễn trung gian

__Điểm mạnh__: do cái IR kia nên sẽ không bị ảnh hưởng bởi kiến trúc. Ngoài ra có cái mối quan hệ giữa parameter-loop giúp tốt hơn việc chỉ dựa vào cấu trúc mẫu

__Điểm yếu__: vẫn còn FP do khó phân biệt function có cấu trúc tương tự nhưng ngữ nghĩa khác nhau

# 4. Path Generation

Có tập source và sinks

```
Sources = {S1,S2,...}
Sinks   = {K1,K2,...}
```

BPDA phải tìm:

S1 → f1 → f2 → K1

S1 → f3 → f4 → K1

S2 → f5 → K2
...

Sẽ sinh path dựa trên quan hệ gọi hàm và dùng IDAPython để trích xuất.

Khi này sẽ xuất hiện vấn đề về nổ path, nghĩa là nếu

```
every source
   ×
every sink
   ×
possible call paths
```

thì có thể tạo ra số lượng path cực lớn mà nếu đưa toàn bộ nào taint không được, hơn nữa có 1 số path mà tham số không phụ thuộc vào input. Do vậy là BPDA có backward phase

# 5. Backward data flow tracking

Giả sử:

```C
void f3(char *input) {

    int x = rand();
    char buf[32];

    strcpy(buf, value_from(x));
}
```

thì tham số value_from(x) kia nó khoong phụ thuộc vào source, nên nếu call graph mà nó vẫn để là source → f1 → f3 → strcpy thì sẽ là sai. Lúc này BPDA bắt đầu từ cái tham số kia, truy ngược lại, nếu cuối cùng không liên hệ với cái source mà có thể điều khiển bởi attacker thì sẽ bỏ path đó đi

```
strcpy(dst, src)
             ↑
          critical

src
 ↑
var3
 ↑
var2
 ↑
...


DROP PATH
```

Cụ thể BPDA sẽ dùng backward tracking trên decompiled pseudocode và phân tích mối quan hệ các biến ở mức code. Nó dùng CTree là cây cú pháp biểu diễn mã giả C, dùng Python truy cập duyệt, phân tích cây này

Có thể hiểu là :

```
IDA decompiler
      ↓
 pseudocode AST
      ↓
    CTree
      ↓
expression / variable relation
      ↓
parameter dependency
```

Nó đệ quy lại:

```
sink argument
      ↑
local variable
      ↑
function argument
      ↑
caller argument
      ↑
...
      ↑
source?
```

Ngoài ra BPDA còn tối ưu hóa filter bằng filter-list, bằng cách là lưu cache của quá trình tỉa. Cụ thể nếu biết hàm A -> hàm B và có tham số x, không phụ thuộc input, thì BPDA sẽ gi lại (function pair, parameter sequence) vào filter list để sau này nếu gặp cùng thì có cache hit sẽ bỏ ngay lập tức để không backward lại

__Điểm mạnh__:  là không phân tích nặng cho tất cả các path

__Điểm yếu__: false negative nếu pseudo recovery sai

# 6. Forward taint analysis

Sau khi cắt tỉa bớt những path, thì những path còn lại thì BPDA sử dụng angr để làm forward taint-analysis. Cụ thể kiểm tra giá trị source từ attacker -> variable -> propagation -> sink

BPDA không chỉ duy trì xem tainted/untainted mà còn theo dõi kiểu dữ liệu

vd : int_ip = atoi(user_input); thì thành user_input string -> atoi()
->  integer representation

BPDA cũng cố nhận diện xem có validate, encoding không __sanitized_input =htmlspecialchars(user_input, ...);__. Nhưng cái này có vẻ cũng chưa ổn lắm do xây pattern library, dựa vào function names nên bị hạn chế

# 7. PoC Generation

Sinh basic PoC dựa vào source type + strings + vuln call + các ràng buộc hàm như strcmp
strcasecmp
strncmp
strstr
memcmp
get_param
get_header
json_get_string
multipart_get_filename
ntohs
inet_addr
atoi
base64_decode
regexec

vd: 

```c
if (strcmp(action, "login") == 0)
    vulnerable_function(input);
```

PoC nhận ra cái ràng buộc action == "login" thì sẽ cố đưa string đó vào input. Tuy nhiên là nó chủ yếu dựa vào mã giả, kiểu source và danh sách hàm ràng buộc chứ không giải đầy đủ. Nên là sẽ có trường hợp phải sàng lọc và xác minh lại

# 8. Chốt lại cái ổn và không của BPDA

## 8.1. OK

Ở mức bao phủ thì : có Sinklens giúp tìm cả những sink chuẩn lẫn custom sinks giúp cải thiện nguồn false negative mà các sink-list hay làm bỏ qua

Hiệu suất: nó không đưa tất cả call path trực tiếp vào taint analysis mà còn có cắt tỉa

Độ chính xác: có suy luận kiểu dữ liệu và filter nên không chỉ làm lan truyền taint kiểu thường

## 8.2. Bất ổn

Phụ thuộc vào static analysis, sinklens vẫn có FP do các hàm giống copy nhưng ngữ nghĩa khác.

Tỉa path cũng nguy cơ false negative do dựa vào mã giả, recovery CTree. Alias, indirect call, global hoặc shared memory có thể khiến mất path quan trọng.

Hiện tại thì sinklens mới tập trung nhiều vào những sink dạng custom memory-copy, chưa làm cho mọi loại 

Phát hiện lọc còn dựa một phần vào những pattern-function name recognition. Những custom lọc có thể bị bỏ sót

PoC generation không hoàn chỉnh