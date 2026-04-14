# Tổng quan

Bài báo khá chi tiết về một hướng mới, bài đã cho 1 con đường khá rõ ràng và hợp lí. Nguồn bài : Ở trong cùng folder

Các kỹ thuật cũ đã bộc lộ nhiều điểm yếu về việc phân tích tĩnh tiềm ẩn dương tính giả cao và không cung cấp được đầy đủ minh chứng, trong khi phân tích động âm tính giả cao. Dương tính giả ở đây là việc kết luận là lỗ hổng nhưng thực tế không phải. Còn âm tính giả là thực sự có lỗ hổng nguy hiểm nhưng lại không tìm thấy và bỏ sót. Để giải quyết vấn đề này, thì đề xuất phương án lai, kết hợp 2 phương pháp và tận dụng LLM trong việc tìm ra lỗ hổng

Thiết kế này sẽ dùng fuzzing(phân tích động với các kiểm thử cơ bản) để xác định chính xác các điểm đầu vào, phân tích tĩnh sẽ phân tích kỹ lưỡng các đường dẫn chương trình bắt đầu từ những điểm đầu vào đó. Dùng LLM để phân tích.

# Giới thiệu ban đầu

Thật ra là việc nghiên cứu firmware mà tích hợp cả phân tích tĩnh và động đã được nghiên cứu và phát triển từ sớm. 

Với phân tích tĩnh, các công cụ của phân tích động như : FirmAFL, SNIPUZZ, FirmFuzz, Greenhouse đã chứng minh được rằng là có thể phát hiện mạnh mẽ lỗ hổng phải khai thác tự động. Tuy nhiên nhược điểm của phân tích tĩnh là độ bao phủ hạn chế, có nghĩa là nó giống kiểu dạng đi sâu, kết quả là còn nhiều cái khác chưa kiểm tra

Với phân tích động, các công cụ : SaTC, Emtaint, HermeScan, OctopusTaint đã có thể bao phủ rộng bằng việc kiểm tra code chương trình mà không thực thi. Tuy nhiên trong phân tích động lại dính phải dương tính giả cao do không biết chính xác điểm nguồn. Không biết rõ về ngữ nghĩa, giống kiểu chỉ biết rõ lý thuyết mà khi vào thực tế thì sẽ rất khác.

Tận dụng thế mạnh của cả 2 cái để bổ sung cho nhau, các nhà nghiên cứu đã phát triển kỹ thuật lai 2 cái là fuzzing động và với phân tích của LLM để vượt qua các kiểm tra phức tạp nhằm mục đích đi sâu nhất có thể. Có thể tóm lược rằng là giống kiểu fuzzing sẽ liên tục khai thác, gặp cản thì sẽ request cho LLM sau đó LLM phản hồi lại phương án để đi tiếp. Như vậy là phương pháp này của các nhà nghiên cứu vướng phải vấn đề là thời gian, độ trễ từ việc gửi đên khi nhận được phản hồi lớn -> tốn thời gian, ngoài ra việc cần ghi lại đường dẫn cũng khá mất thời gian. Hơn nữa, do là fuzzing lai cho IOT trên Linux nên là khó trong việc thu thập dữ liệu về thời gian do là chạy trên môi trường giả lập.

Tác giả đã thực nghiệm thử và thấy rằng fuzzing hiệu quả trong việc tìm ra đầu vào, nhưng tác giả cũng nhận ra rằng nếu với các điều kiện kiểm tra tham số nghiêm ngặt và logic điều khiển phức tạp thì nhiều cái vẫn không thể tiếp cận được -> âm tính giả. Còn tĩnh thì vượt qua ràng buộc đầu 