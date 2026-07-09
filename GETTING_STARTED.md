# Getting Started with AvSuite | Bắt Đầu Với AvSuite

## The Story | Câu Chuyện

AvSuite is a **research project** that demonstrates how to build a Windows kernel-mode security system. It's not a production antivirus, but rather an educational example of:

- How kernel drivers work (WDM minifilter architecture)
- How to monitor file system operations in real-time
- How to implement threat detection rules
- How to design security systems that respect system performance

AvSuite là một **dự án nghiên cứu** minh họa cách xây dựng một hệ thống bảo mật ở chế độ kernel Windows. Đây không phải antivirus sản xuất, mà là một ví dụ giáo dục về:

- Cách driver kernel hoạt động (kiến trúc WDM minifilter)
- Cách giám sát các thao tác hệ thống tệp theo thời gian thực
- Cách triển khai các quy tắc phát hiện mối đe dọa
- Cách thiết kế các hệ thống bảo mật tôn trọng hiệu suất hệ thống

---

## Why This Matters | Tại Sao Điều Này Quan Trọng

**For Security Engineers:**
Understanding kernel-mode security is critical. Most antivirus/EDR systems operate at this level. This project shows the fundamentals.

**Cho Kỹ Sư Bảo Mật:**
Hiểu bảo mật ở chế độ kernel rất quan trọng. Hầu hết các hệ thống antivirus/EDR hoạt động ở mức độ này. Dự án này cho thấy các nguyên tắc cơ bản.

**For System Designers:**
How do you balance security with performance? How do you decide what to monitor? This project explores these trade-offs.

**Cho Nhà Thiết Kế Hệ Thống:**
Làm thế nào để cân bằng bảo mật với hiệu suất? Làm thế nào để quyết định những gì cần giám sát? Dự án này khám phá các sự đánh đổi này.

**For Learners:**
This is a complete example of kernel driver development with real testing. You can study the code, run it in a VM, and see it actually work.

**Cho Những Người Học:**
Đây là một ví dụ hoàn chỉnh về phát triển driver kernel với kiểm tra thực tế. Bạn có thể nghiên cứu mã, chạy nó trong VM, và xem nó hoạt động thực tế.

---

## What You'll Learn | Những Gì Bạn Sẽ Học

✅ **Windows Driver Development**
- How minifilter drivers intercept file operations
- How to handle I/O requests safely
- How to manage driver lifecycle

✅ **Phát Triển Driver Windows**
- Cách minifilter driver chặn các thao tác tệp
- Cách xử lý các yêu cầu I/O một cách an toàn
- Cách quản lý vòng đời driver

---

✅ **Kernel-Mode Programming**
- Ring 0 execution context
- Interrupt and DPC handling
- Resource synchronization

✅ **Lập Trình Ở Chế Độ Kernel**
- Bối cảnh thực thi Ring 0
- Xử lý ngắt và DPC
- Đồng bộ hóa tài nguyên

---

✅ **Security Architecture**
- Behavior-based detection patterns
- Real-time decision making
- Event logging and auditing

✅ **Kiến Trúc Bảo Mật**
- Mô hình phát hiện dựa trên hành vi
- Quyết định theo thời gian thực
- Ghi nhật ký sự kiện và kiểm tra

---

✅ **Professional Practices**
- Code signing (self-signed for testing)
- Security testing methodology
- Honest documentation of limitations

✅ **Thực Hành Chuyên Nghiệp**
- Ký mã (tự-ký cho kiểm tra)
- Phương pháp kiểm tra bảo mật
- Tài liệu chân thực về những hạn chế

---

## Installation & Testing | Cài Đặt & Kiểm Tra

### Prerequisites | Yêu Cầu Tiên Quyết

**Hardware:**
- Windows 11 VM (VMware, VirtualBox, or Hyper-V)
- At least 4GB RAM
- 20GB disk space

**Phần Cứng:**
- Windows 11 VM (VMware, VirtualBox, hoặc Hyper-V)
- Ít nhất 4GB RAM
- Không gian đĩa 20GB

**Software:**
- Visual Studio 2022 (to rebuild if desired)
- PowerShell (for certificate generation)

**Phần Mềm:**
- Visual Studio 2022 (nếu muốn xây dựng lại)
- PowerShell (để tạo chứng chỉ)

### Step 1: Clone Repository | Bước 1: Sao Chép Kho Lưu Trữ

```bash
git clone https://github.com/teohumble1/avsuite.git
cd avsuite
```

```bash
git clone https://github.com/teohumble1/avsuite.git
cd avsuite
```

### Step 2: Read the Documentation | Bước 2: Đọc Tài Liệu

**Start here (in order):**
1. `README.md` - Project overview (English + Tiếng Việt)
2. `INSTALLATION.md` - Detailed setup instructions
3. `TEST-RESULTS.md` - What was actually tested
4. `STATUS.md` - Component completion status

**Bắt đầu từ đây (theo thứ tự):**
1. `README.md` - Tổng quan dự án (English + Tiếng Việt)
2. `INSTALLATION.md` - Hướng dẫn thiết lập chi tiết
3. `TEST-RESULTS.md` - Những gì được kiểm tra thực tế
4. `STATUS.md` - Trạng thái hoàn thành thành phần

### Step 3: Prepare Windows 11 VM | Bước 3: Chuẩn Bị Windows 11 VM

⚠️ **IMPORTANT: Use an isolated VM only!**

⚠️ **QUAN TRỌNG: Chỉ sử dụng VM cách ly!**

Follow the setup guide in `README.md`:
1. Disable Secure Boot (VM settings)
2. Enable Test-Signing Mode (`bcdedit /set testsigning on`)
3. Generate certificate (`powershell -File generate-cert.ps1`)
4. Install certificate (see README.md Step 4)
5. Install driver (see README.md Step 5)

Làm theo hướng dẫn thiết lập trong `README.md`:
1. Tắt Khởi Động Bảo Mật (cài đặt VM)
2. Bật Chế Độ Ký Kiểm Tra (`bcdedit /set testsigning on`)
3. Tạo chứng chỉ (`powershell -File generate-cert.ps1`)
4. Cài đặt chứng chỉ (xem README.md Bước 4)
5. Cài đặt driver (xem README.md Bước 5)

### Step 4: Run Tests | Bước 4: Chạy Kiểm Tra

**Option A: Manual Testing**

```cmd
# Create a test file
echo "This is a test" > C:\temp\test.txt

# Monitor the driver
fltmc instances

# Check event log (driver creates events)
# Look in Event Viewer → Windows Logs → System
```

**Tùy chọn A: Kiểm Tra Thủ Công**

```cmd
# Tạo tệp kiểm tra
echo "This is a test" > C:\temp\test.txt

# Giám sát driver
fltmc instances

# Kiểm tra nhật ký sự kiện (driver tạo sự kiện)
# Tìm trong Event Viewer → Windows Logs → System
```

**Option B: Reproduce Published Tests**

See `TEST-RESULTS.md` for the exact test corpus that was run. Try to reproduce the same results.

**Tùy chọn B: Tái Tạo Các Bài Kiểm Tra Công Bố**

Xem `TEST-RESULTS.md` cho tập hợp kiểm tra chính xác đã chạy. Cố gắng tái tạo các kết quả tương tự.

---

## Understanding the Code | Hiểu Mã

### Directory Structure | Cấu Trúc Thư Mục

```
avsuite/
├── driver/
│   └── AvMiniFilter/        # Kernel driver source + binary
│                              # Nguồn driver kernel + nhị phân
├── src/
│   ├── pe_analyzer/         # Signature matching engine
│   │                          # Engine matching chữ ký
│   ├── static_scan/         # YARA rule engine
│   │                          # Engine quy tắc YARA
│   └── behavior_engine/     # Behavior pattern detection
│                              # Phát hiện mô hình hành vi
├── README.md                # Project overview (THIS FILE)
├── INSTALLATION.md          # Setup instructions
├── TEST-RESULTS.md          # Testing report
├── STATUS.md                # Component status
└── generate-cert.ps1        # Certificate generator
```

### Key Files to Study | Các Tệp Chính Để Nghiên Cứu

**Start with:**
1. `driver/AvMiniFilter/AvMiniFilter.c` - Main driver code
2. `src/behavior_engine/rule_engine.cpp` - How rules are evaluated
3. `TEST-RESULTS.md` - See what actually works

**Bắt đầu với:**
1. `driver/AvMiniFilter/AvMiniFilter.c` - Mã driver chính
2. `src/behavior_engine/rule_engine.cpp` - Cách đánh giá quy tắc
3. `TEST-RESULTS.md` - Xem những gì hoạt động thực tế

---

## Common Questions | Các Câu Hỏi Thường Gặp

**Q: Is this production antivirus?**
A: No. It's a research/educational project to understand kernel security architecture. Real AV requires 6-12 months of testing.

**H: Đây có phải là antivirus sản xuất không?**
Đ: Không. Đây là một dự án nghiên cứu/giáo dục để hiểu kiến trúc bảo mật kernel. AV thực yêu cầu 6-12 tháng kiểm tra.

---

**Q: Can I use this on production systems?**
A: No. It's tested only on isolated VMs with test-signing enabled. Production would require:
- Months of malware testing
- False positive analysis
- Performance optimization
- EV certificate from trusted CA

**H: Tôi có thể sử dụng cái này trên các hệ thống sản xuất không?**
Đ: Không. Nó chỉ được kiểm tra trên các VM cách ly với ký kiểm tra được bật. Sản xuất sẽ yêu cầu:
- Hàng tháng kiểm tra malware
- Phân tích dương tính giả
- Tối ưu hóa hiệu suất
- Chứng chỉ EV từ CA đáng tin cậy

---

**Q: What can I learn from this?**
A: Windows kernel programming, driver development, security architecture, real-time monitoring, threat detection concepts, and professional documentation practices.

**H: Tôi có thể học được gì từ điều này?**
Đ: Lập trình kernel Windows, phát triển driver, kiến trúc bảo mật, giám sát thời gian thực, các khái niệm phát hiện mối đe dọa, và các thực hành tài liệu chuyên nghiệp.

---

**Q: Can I modify and redistribute this?**
A: Yes, it's MIT licensed. See LICENSE file. Just maintain the license header and document your changes.

**H: Tôi có thể sửa đổi và phân phối lại cái này không?**
Đ: Có, nó được cấp phép MIT. Xem tệp LICENSE. Chỉ cần duy trì tiêu đề giấy phép và ghi lại các thay đổi của bạn.

---

## Troubleshooting | Xử Lý Sự Cố

**Driver won't load**
- Verify Test-Signing Mode is ON: `bcdedit /query testsigning`
- Verify Secure Boot is disabled (check VM BIOS)
- Verify certificate is installed to Trusted Root
- Check Event Viewer → Windows Logs → System for errors

**Driver không tải được**
- Xác minh Chế độ Ký Kiểm Tra là BẬT: `bcdedit /query testsigning`
- Xác minh Khởi Động Bảo Mật bị tắt (kiểm tra BIOS VM)
- Xác minh chứng chỉ được cài đặt vào Gốc Đáng Tin Cậy
- Kiểm tra Event Viewer → Windows Logs → System để xem lỗi

---

**Certificate installation fails**
- Run PowerShell as Administrator
- Check certificate file path is correct
- Verify you're in an isolated VM only

**Cài đặt chứng chỉ thất bại**
- Chạy PowerShell dưới quyền Quản trị viên
- Kiểm tra đường dẫn tệp chứng chỉ là chính xác
- Xác minh bạn chỉ ở trong VM cách ly

---

## Next Steps | Bước Tiếp Theo

1. **Study the code** - Understand the architecture
2. **Run in a VM** - See it actually work
3. **Read TEST-RESULTS.md** - Understand limitations
4. **Explore modifications** - Extend for your learning
5. **Share feedback** - Help improve this project

---

1. **Nghiên cứu mã** - Hiểu kiến trúc
2. **Chạy trong VM** - Xem nó hoạt động thực tế
3. **Đọc TEST-RESULTS.md** - Hiểu những hạn chế
4. **Khám phá sửa đổi** - Mở rộng để học
5. **Chia sẻ phản hồi** - Giúp cải thiện dự án này

---

## Resources | Các Tài Nguyên

- `README.md` - Full project overview
- `INSTALLATION.md` - Detailed setup guide
- `TEST-RESULTS.md` - Testing methodology & results
- `STATUS.md` - Component completion breakdown
- GitHub Issues - Ask questions, share findings

---

## License | Giấy Phép

MIT License - See LICENSE file for details.

You're free to use this for learning, research, and educational purposes.

Bạn có thể tự do sử dụng cái này cho mục đích học tập, nghiên cứu và giáo dục.

---

**Happy learning! 🎓**

**Học tập vui vẻ! 🎓**
