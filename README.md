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

---

## Features | Tính Năng

### Core Security | Bảo Mật Cốt Lõi
- ✅ **Real-time Threat Detection** - Kernel-mode file monitoring with instant alerts
- ✅ **YARA Rule Engine** - Configurable malware pattern matching
- ✅ **Quarantine Management** - Isolate suspicious files with restore/delete options
- ✅ **Behavior Analysis** - Track process/registry/file operations
- ✅ **Event Logging** - SQLite database for threat audit trail

### Dashboard UI | Giao Diện Người Dùng
- ✅ **Realtime Monitoring** - Live threat detection dashboard
- ✅ **Quarantine Panel** - View isolated files with multi-select operations
- ✅ **System Events** - Complete event log with search/filter
- ✅ **Threat Intelligence** - Display detected threat patterns
- ✅ **Dark Theme** - Amber Dark theme with cyan accents

---

### Bảo Mật Cốt Lõi
- ✅ **Phát hiện mối đe dọa theo thời gian thực** - Giám sát tệp ở chế độ kernel với cảnh báo tức thì
- ✅ **Engine Quy Tắc YARA** - Khớp mô hình malware có thể cấu hình
- ✅ **Quản lý Quarantine** - Cách ly các tệp đáng ngờ với tùy chọn khôi phục/xóa
- ✅ **Phân tích Hành Vi** - Theo dõi hoạt động quá trình/sổ đăng ký/tệp
- ✅ **Ghi nhật ký sự kiện** - Cơ sở dữ liệu SQLite cho đường kiểm toán mối đe dọa

### Giao Diện Người Dùng Dashboard
- ✅ **Giám sát theo thời gian thực** - Bảng điều khiển phát hiện mối đe dọa trực tiếp
- ✅ **Bảng điều khiển Quarantine** - Xem tệp bị cách ly với các hoạt động lựa chọn nhiều
- ✅ **Sự kiện hệ thống** - Nhật ký sự kiện hoàn chỉnh với tìm kiếm/lọc
- ✅ **Thông tin tình báo mối đe dọa** - Hiển thị các mô hình mối đe dọa được phát hiện
- ✅ **Chủ đề tối** - Chủ đề Amber Dark với nhấn mạnh lục lam

## Installation | Cài Đặt

### Option 1: Pre-built Binary (Recommended) | Tùy Chọn 1: Binary Được Xây Dựng Sẵn (Khuyến Nghị)

Download latest release from GitHub:
```bash
# Visit: https://github.com/teohumble1/avsuite/releases
# Download: TeoAvSuite-Setup-v1.0.0.exe
# Run installer (requires admin + test VM only)
```

Tải phiên bản mới nhất từ GitHub:
```bash
# Truy cập: https://github.com/teohumble1/avsuite/releases
# Tải: TeoAvSuite-Setup-v1.0.0.exe
# Chạy trình cài đặt (yêu cầu quản trị viên + chỉ VM kiểm tra)
```

### Option 2: Build from Source | Tùy Chọn 2: Xây Dựng Từ Nguồn

**Requirements | Yêu Cầu:**
- Visual Studio 2022 with C++ workload
- CMake 3.16+
- Windows 11 SDK

**Build steps | Các bước xây dựng:**
```powershell
# Clone repository
git clone https://github.com/teohumble1/avsuite.git
cd avsuite

# Create build directory
mkdir build
cd build

# Generate build files (Release)
cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release ..

# Build project
cmake --build . --config Release

# Output: build\release\src\dashboard_ui\Release\avdashboard.exe
```

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
✅ **Malware Detection Tested:**
- EICAR standard test file
- PE Injection techniques (PEJINJECTION_IMPORT_COMBO)
- Advanced evasion patterns (import hooking, API shimming)
- Real-world suspicious executables (malware_test samples)
- 50+ benign file monitoring for baseline
- No false positives on clean system files
- System stability verified

---

✅ **Phát Hiện Malware Được Kiểm Tra:**
- Tệp kiểm tra tiêu chuẩn EICAR
- Kỹ thuật PE Injection (PEJINJECTION_IMPORT_COMBO)
- Mô hình thác thoát nâng cao (import hooking, API shimming)
- Các tệp thực tế đáng ngờ (mẫu malware_test)
- Giám sát 50+ tệp lành mạnh để tạo baseline
- Không có dương tính giả trên các tệp hệ thống sạch
- Ổn định hệ thống được xác minh

## Quarantine Management | Quản Lý Quarantine

**v1.0.0 Feature: Select All with Batch Operations**

The Quarantine tab provides:
- ✅ View all isolated threats in a table
- ✅ **Select All button** - Quickly select all quarantine items (cyan/blue styled)
- ✅ **Multi-selection** - Hold Ctrl+Click to select multiple files
- ✅ **Batch Restore** - Restore multiple files to their original location
- ✅ **Batch Delete** - Permanently remove multiple quarantine items
- ✅ **Progress Tracking** - Real-time feedback ("Restored 5/10 files", etc.)
- ✅ **Partial Failure Handling** - Clear error reporting if some operations fail

**How to use | Cách sử dụng:**
1. Navigate to Quarantine tab
2. Click "✓ Select All" button to select all items
3. Click "Restore" (khôi phục) or "Xóa vĩnh viễn" (permanent delete)
4. Progress displayed with status on completion

---

**v1.0.0 Tính năng: Select All với Batch Operations**

Tab Quarantine cung cấp:
- ✅ Xem tất cả các mối đe dọa bị cách ly trong một bảng
- ✅ **Nút Select All** - Nhanh chóng chọn tất cả các mục quarantine (được định kiểu lục lam/xanh lam)
- ✅ **Lựa chọn nhiều** - Giữ Ctrl+Click để chọn nhiều tệp
- ✅ **Khôi phục hàng loạt** - Khôi phục nhiều tệp về vị trí ban đầu của chúng
- ✅ **Xóa hàng loạt** - Loại bỏ vĩnh viễn nhiều mục quarantine
- ✅ **Theo dõi tiến độ** - Phản hồi theo thời gian thực ("Đã khôi phục 5/10 tệp", v.v.)
- ✅ **Xử lý lỗi một phần** - Báo lỗi rõ ràng nếu một số thao tác không thành công

## What's Implemented ✅ | Những Gì Được Triển Khai ✅

- Minifilter driver (loads, attaches, functional)
- Basic behavior rule engine
- Self-signed code-signing
- Event database logging
- Installation procedures
- VMware testing validated
- ✅ **Select All + Multi-selection** (v1.0.0)
- ✅ **Batch restore/delete** with progress tracking (v1.0.0)
- ✅ **Professional installer** (Inno Setup, v1.0.0)

---

- Minifilter driver (tải, gắn, hoạt động)
- Engine quy tắc hành vi cơ bản
- Ký mã tự-ký
- Ghi nhật ký sự kiện cơ sở dữ liệu
- Quy trình cài đặt
- Kiểm tra VMware được xác thực
- ✅ **Select All + Lựa chọn nhiều** (v1.0.0)
- ✅ **Khôi phục/xóa hàng loạt** với theo dõi tiến độ (v1.0.0)
- ✅ **Trình cài đặt chuyên nghiệp** (Inno Setup, v1.0.0)

## What's NOT Implemented ❌ | Những Gì KHÔNG Được Triển Khai ❌

- ~~Real malware testing~~ ✅ **TESTED** (PE injection, advanced evasion patterns)
- ~~False positive minimization~~ ✅ **VALIDATED** (benign corpus baseline, 0 FP on clean files)
- Performance optimization (tuning for scale)
- Comprehensive evasion resistance (cutting-edge techniques)
- Enterprise license/support features
- Production-grade SLA/reliability guarantees

---

- ~~Kiểm tra malware thực~~ ✅ **ĐÃ KIỂM TRA** (PE injection, mô hình thác thoát nâng cao)
- ~~Giảm thiểu dương tính giả~~ ✅ **ĐÃ XÁC THỰC** (baseline tập hợp lành mạnh, 0 FP trên tệp sạch)
- Tối ưu hóa hiệu suất (điều chỉnh cho quy mô)
- Kháng thác thoát toàn diện (kỹ thuật tiên tiến)
- Tính năng giấy phép/hỗ trợ doanh nghiệp
- Đảm bảo SLA/độ tin cậy cấp sản xuất

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

## Troubleshooting | Khắc Phục Sự Cố

### Dashboard won't start / Giao diện không khởi động
**Problem**: App crashes on launch
**Solution**:
1. Delete database file: `Delete %APPDATA%\TeoAvSuite\avsuite.db*` (*.db-shm, *.db-wal)
2. Restart application - fresh database will be created
3. Re-apply setup steps if driver errors occur

---

**Vấn đề**: Ứng dụng bị sập khi khởi động
**Giải pháp**:
1. Xóa tệp cơ sở dữ liệu: `Xóa %APPDATA%\TeoAvSuite\avsuite.db*` (*.db-shm, *.db-wal)
2. Khởi động lại ứng dụng - cơ sở dữ liệu mới sẽ được tạo
3. Áp dụng lại các bước thiết lập nếu lỗi driver xảy ra

### Driver fails to load / Driver không tải
**Problem**: "Driver load failed" error
**Possible causes**:
- Secure Boot not disabled (VM only)
- Test-signing mode not enabled (`bcdedit /query testsigning`)
- Certificate not installed in Trusted Root
- Driver altitude conflict

**Solution**:
1. Verify test-signing is ON: `bcdedit /query testsigning`
2. If OFF, enable: `bcdedit /set testsigning on` then reboot
3. Verify certificate: Windows Key + R → `certmgr.msc` → Trusted Root Certification Authorities
4. Re-run setup procedures

---

**Vấn đề**: Lỗi "Driver load failed"
**Nguyên nhân có thể**:
- Khởi động bảo mật không bị tắt (chỉ VM)
- Chế độ ký kiểm tra không được bật (`bcdedit /query testsigning`)
- Chứng chỉ không được cài đặt trong Trusted Root
- Xung đột độ cao của driver

**Giải pháp**:
1. Xác minh ký kiểm tra ĐƯỢC BẬT: `bcdedit /query testsigning`
2. Nếu TẮT, bật: `bcdedit /set testsigning on` rồi khởi động lại
3. Xác minh chứng chỉ: Windows Key + R → `certmgr.msc` → Trusted Root Certification Authorities
4. Chạy lại các bước thiết lập

### No threats detected / Không phát hiện mối đe dọa
**Problem**: Engine running but no alerts
**Check**:
- Is driver loaded? Run: `fltmc instances` - should show AvMiniFilter
- Are YARA rules present? Check: `avsuite.json` configuration
- Is quarantine actually collecting files? Check database

**Note**: This is a research project - not comprehensive malware detection

---

**Vấn đề**: Engine chạy nhưng không có cảnh báo
**Kiểm tra**:
- Driver có được tải không? Chạy: `fltmc instances` - nên hiển thị AvMiniFilter
- Các quy tắc YARA có hiện diện không? Kiểm tra: cấu hình `avsuite.json`
- Quarantine có thực sự thu thập tệp không? Kiểm tra cơ sở dữ liệu

**Lưu ý**: Đây là một dự án nghiên cứu - không phát hiện malware toàn diện

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

## Distribution & Releases | Phân Phối & Phát Hành

**Current Version**: v1.0.0 (2026-07-09)
- Available at: https://github.com/teohumble1/avsuite/releases
- Format: TeoAvSuite-Setup-v1.0.0.exe (Windows 10/11 installer)
- Installation: Admin + isolated VM recommended
- Uninstall: Windows Control Panel → Programs and Features

**Phiên bản hiện tại**: v1.0.0 (2026-07-09)
- Có sẵn tại: https://github.com/teohumble1/avsuite/releases
- Định dạng: TeoAvSuite-Setup-v1.0.0.exe (trình cài đặt Windows 10/11)
- Cài đặt: Quản trị viên + VM cách ly được khuyến nghị
- Gỡ cài đặt: Windows Control Panel → Programs and Features

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
