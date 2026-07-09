# AvSuite - Windows Kernel Security Research Project
# AvSuite - Dự Án Nghiên Cứu Bảo Mật Kernel Windows

![Platform](https://img.shields.io/badge/platform-Windows%2011-blue)
![Status](https://img.shields.io/badge/status-Research%20Project-blue)

A portfolio security research project demonstrating Windows kernel-mode threat detection and behavior analysis. **Not for production use.**

Dự án portfolio nghiên cứu bảo mật minh họa phát hiện mối đe dọa ở chế độ kernel Windows và phân tích hành vi. **Không dành cho sử dụng sản xuất.**

## What This Is | Đây Là Cái Gì

This is an **educational/research project** that implements:
- Kernel minifilter driver (WDM architecture)
- Behavior-based threat detection patterns
- Real-time filesystem monitoring
- Self-signed code-signing infrastructure

**This is NOT production antivirus.** It demonstrates systems programming and security architecture knowledge.

---

Đây là một **dự án giáo dục/nghiên cứu** thực hiện:
- Minifilter driver kernel (kiến trúc WDM)
- Mô hình phát hiện mối đe dọa dựa trên hành vi
- Giám sát hệ thống tệp theo thời gian thực
- Cơ sở hạ tầng ký mã tự-ký

**Đây KHÔNG phải antivirus sản xuất.** Nó minh họa kiến thức lập trình hệ thống và thiết kế kiến trúc bảo mật.

## Technical Implementation | Triển Khai Kỹ Thuật

### Kernel Driver | Driver Kernel
- **Language**: C
- **Architecture**: WDM minifilter
- **Size**: 16.6 KB (optimized)
- **Status**: Functional, tested on Windows 11 VMware
- **Signing**: Self-signed certificate (SHA256)

---

- **Ngôn ngữ**: C
- **Kiến trúc**: WDM minifilter
- **Kích thước**: 16,6 KB (tối ưu hóa)
- **Trạng thái**: Hoạt động, được kiểm tra trên Windows 11 VMware
- **Ký**: Chứng chỉ tự-ký (SHA256)

### Behavior Engine | Engine Hành Vi
- Configurable pattern detection
- File/registry/process monitoring
- Event logging to SQLite database
- Real-time decision making

---

- Phát hiện mô hình có thể cấu hình
- Giám sát tệp/đăng ký/quá trình
- Ghi nhật ký sự kiện vào cơ sở dữ liệu SQLite
- Quyết định theo thời gian thực

### Testing | Kiểm Tra
- EICAR standard test file
- 50+ benign file monitoring
- No system crashes
- Stable operation verified

---

- Tệp kiểm tra tiêu chuẩn EICAR
- Giám sát 50+ tệp lành mạnh
- Không có sự cố hệ thống
- Hoạt động ổn định được xác minh

## What's Implemented ✅ | Những Gì Được Triển Khai ✅

- Minifilter driver (loads, attaches, functional)
- Basic behavior rule engine
- Self-signed code-signing
- Event database logging
- Installation procedures
- VMware testing validated

---

- Minifilter driver (tải, gắn, hoạt động)
- Engine quy tắc hành vi cơ bản
- Ký mã tự-ký
- Ghi nhật ký sự kiện cơ sở dữ liệu
- Quy trình cài đặt
- Kiểm tra VMware được xác thực

## What's NOT Implemented ❌ | Những Gì KHÔNG Được Triển Khai ❌

- Real malware testing (zero samples tested)
- False positive minimization (no benign corpus)
- Performance optimization
- Evasion resistance
- Enterprise features
- Production-grade reliability

---

- Kiểm tra malware thực (không có mẫu nào được kiểm tra)
- Giảm thiểu dương tính giả (không có tập hợp lành mạnh)
- Tối ưu hóa hiệu suất
- Kháng thác thoát
- Tính năng doanh nghiệp
- Độ tin cậy cấp sản xuất

## Quick Start | Bắt Đầu Nhanh

### Prerequisites | Yêu Cầu Tiên Quyết
- Windows 11 (x64)
- Administrator access
- Visual Studio 2022 (to rebuild)
- **TEST ENVIRONMENT ONLY** - This is not for production systems

---

- Windows 11 (x64)
- Quyền truy cập quản trị viên
- Visual Studio 2022 (để xây dựng lại)
- **CHỈ MÔI TRƯỜNG KIỂM TRA** - Đây không phải cho hệ thống sản xuất

### Setup (Windows 11 VM Only) | Thiết Lập (Chỉ VM Windows 11)

⚠️ **IMPORTANT: This procedure is for isolated testing VMs only.**

⚠️ **QUAN TRỌNG: Quy trình này chỉ dành cho các VM kiểm tra cách ly.**

#### Step 1: Disable Secure Boot (VM only) | Bước 1: Tắt Khởi Động Bảo Mật (Chỉ VM)
```cmd
# In VMware VM BIOS/UEFI
# Disable Secure Boot before installing driver
```

```cmd
# Trong BIOS/UEFI VM VMware
# Tắt Khởi Động Bảo Mật trước khi cài đặt driver
```

#### Step 2: Enable Test-Signing Mode | Bước 2: Bật Chế Độ Ký Kiểm Tra
```cmd
# Run as Administrator
bcdedit /set testsigning on

# Reboot required
shutdown /r /t 0
```

```cmd
# Chạy dưới quyền Quản trị viên
bcdedit /set testsigning on

# Cần khởi động lại
shutdown /r /t 0
```

#### Step 3: Generate Self-Signed Certificate | Bước 3: Tạo Chứng Chỉ Tự-Ký
```powershell
# Run as Administrator (in repo directory)
powershell -ExecutionPolicy Bypass -File .\generate-cert.ps1
```

```powershell
# Chạy dưới quyền Quản trị viên (trong thư mục repo)
powershell -ExecutionPolicy Bypass -File .\generate-cert.ps1
```

#### Step 4: Install Certificate to Trusted Root | Bước 4: Cài Đặt Chứng Chỉ Vào Gốc Đáng Tin Cậy
```powershell
# Run as Administrator
# WARNING: Only do this in isolated test VMs
# This adds an untrusted root certificate to your system

$cert = Get-PfxCertificate -FilePath "avsuite_cert.pfx"
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

Write-Host "Certificate installed"
```

```powershell
# Chạy dưới quyền Quản trị viên
# CẢNH BÁO: Chỉ thực hiện việc này trong các VM kiểm tra cách ly
# Thao tác này thêm chứng chỉ gốc không đáng tin cậy vào hệ thống của bạn

$cert = Get-PfxCertificate -FilePath "avsuite_cert.pfx"
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

Write-Host "Chứng chỉ được cài đặt"
```

#### Step 5: Install Driver | Bước 5: Cài Đặt Driver
```cmd
# Copy signed driver
copy avsuite_driver.sys C:\Windows\System32\drivers\AvMiniFilter.sys

# Create service
sc create AvMiniFilter binPath= "C:\Windows\System32\drivers\AvMiniFilter.sys" type= kernel

# Start
net start AvMiniFilter

# Verify
fltmc instances
```

```cmd
# Sao chép driver đã ký
copy avsuite_driver.sys C:\Windows\System32\drivers\AvMiniFilter.sys

# Tạo dịch vụ
sc create AvMiniFilter binPath= "C:\Windows\System32\drivers\AvMiniFilter.sys" type= kernel

# Bắt đầu
net start AvMiniFilter

# Xác minh
fltmc instances
```

## Important Limitations | Những Hạn Chế Quan Trọng

### Security | Bảo Mật
- **Self-signed certificate only** - not from trusted CA
- No real malware tested against
- Not resistant to sophisticated evasion
- No zero-day detection capability

---

- **Chỉ chứng chỉ tự-ký** - không từ CA đáng tin cậy
- Không có malware thực được kiểm tra
- Không kháng được thác thoát tinh vi
- Không có khả năng phát hiện zero-day

### Performance | Hiệu Suất
- Not optimized for production workloads
- Simplified rule evaluation
- No caching mechanisms
- Not benchmarked under load

---

- Không được tối ưu hóa cho khối lượng công việc sản xuất
- Đánh giá quy tắc đơn giản hóa
- Không có cơ chế bộ nhớ đệm
- Không được chuẩn bị đo tải

### Completeness | Tính Hoàn Chỉnh
- Dashboard UI is framework-level only
- ETW integration incomplete
- No machine learning models
- Limited threat pattern coverage

---

- Giao diện người dùng Dashboard chỉ ở mức framework
- Tích hợp ETW không hoàn chỉnh
- Không có mô hình học máy
- Phạm vi mô hình mối đe dọa hạn chế

## Testing Results | Kết Quả Kiểm Tra

**Real test execution (2026-07-09):**
- EICAR standard test file: ✅ Created
- Benign files (50): ✅ Monitored
- Driver instances: ✅ 3 active on C: drive
- System stability: ✅ No crashes
- Altitude: 385101 ✅ Correct

**Important note:** This is NOT comprehensive testing. Real AV requires:
- 1M+ real malware samples
- 1M+ benign application binaries
- False positive rate evaluation
- Performance stress testing
- Evasion technique resistance

---

**Thực thi kiểm tra thực tế (2026-07-09):**
- Tệp kiểm tra tiêu chuẩn EICAR: ✅ Đã tạo
- Tệp lành mạnh (50): ✅ Được giám sát
- Phiên bản driver: ✅ 3 hoạt động trên ổ C:
- Ổn định hệ thống: ✅ Không có sự cố
- Độ cao: 385101 ✅ Chính xác

**Ghi chú quan trọng:** Đây KHÔNG phải là kiểm tra toàn diện. AV thực yêu cầu:
- 1M+ mẫu malware thực
- 1M+ tệp nhị phân ứng dụng lành mạnh
- Đánh giá tỷ lệ dương tính giả
- Kiểm tra căng thẳng hiệu suất
- Kháng lại kỹ thuật thác thoát

## For Portfolio Review | Để Xem Xét Portfolio

### What This Demonstrates | Những Gì Được Minh Họa
✅ Windows kernel programming
✅ Driver development knowledge
✅ Security architecture design
✅ Code-signing practices
✅ Professional documentation
✅ Realistic scoping

---

✅ Lập trình kernel Windows
✅ Kiến thức phát triển driver
✅ Thiết kế kiến trúc bảo mật
✅ Thực hành ký mã
✅ Tài liệu chuyên nghiệp
✅ Phạm vi thực tế

### What This Does NOT Claim | Những Gì Điều Này KHÔNG Tuyên Bố
❌ Production-ready antivirus
❌ Enterprise-grade reliability
❌ Tested on real malware
❌ Zero false positives
❌ Performance-optimized

---

❌ Antivirus sẵn sàng sản xuất
❌ Độ tin cậy cấp doanh nghiệp
❌ Được kiểm tra trên malware thực
❌ Không có dương tính giả
❌ Tối ưu hóa hiệu suất

## Files | Các Tệp

- `driver/AvMiniFilter/` - Kernel driver source + binary | Kernel driver nguồn + nhị phân
- `src/` - Core engine code | Mã engine cốt lõi
- `.gitignore` - Protects secrets (*.pfx, etc) | Bảo vệ bí mật (*.pfx, v.v.)
- `STATUS.md` - Component completion tracking | Theo dõi hoàn thành thành phần
- `TEST-RESULTS.md` - Real testing data | Dữ liệu kiểm tra thực tế
- `generate-cert.ps1` - Create self-signed certificate | Tạo chứng chỉ tự-ký

## Interview Talking Points | Những Điểm Nói Chuyện Phỏng Vấn

**"Is this production-ready?"**
> No - it's a research project to demonstrate kernel architecture and security concepts. Production AV needs months of malware testing and false positive tuning.

**"Điều này có sẵn sàng sản xuất không?"**
> Không - đây là một dự án nghiên cứu để minh họa kiến trúc kernel và các khái niệm bảo mật. AV sản xuất cần hàng tháng kiểm tra malware và tinh chỉnh dương tính giả.

---

**"Why self-signed certificate?"**
> For portfolio purposes. Production would use EV certificate from trusted CA. The important part is showing I understand code-signing practices.

**"Tại sao chứng chỉ tự-ký?"**
> Cho mục đích portfolio. Sản xuất sẽ sử dụng chứng chỉ EV từ CA đáng tin cậy. Phần quan trọng là cho thấy tôi hiểu các thực hành ký mã.

---

**"How would you make it production?"**
> Real malware corpus testing, false positive minimization, performance optimization, enterprise features - that's 6-12 months of team work.

**"Bạn sẽ làm nó sản xuất như thế nào?"**
> Kiểm tra tập hợp malware thực, giảm thiểu dương tính giả, tối ưu hóa hiệu suất, tính năng doanh nghiệp - đó là công việc 6-12 tháng của một đội.

## Learning Resources | Các Tài Nguyên Học Tập

See `STATUS.md` for detailed component breakdown of what's complete vs. what's framework-level.

Xem `STATUS.md` để xem phân tích chi tiết thành phần về những gì hoàn thành so với những gì ở mức framework.

## Author | Tác Giả

Teohumble - Security Research & Development | Nghiên Cứu & Phát Triển Bảo Mật

---

**Project Status**: Research/Portfolio | Trạng thái Dự án: Nghiên Cứu/Portfolio  
**Platform**: Windows 11  
**Build Status**: Clean (Debug + Release) | Trạng thái Xây dựng: Sạch (Debug + Release)  
**Testing**: VMware validated | Kiểm tra: VMware được xác thực  
**Repository**: https://github.com/teohumble1/avsuite
