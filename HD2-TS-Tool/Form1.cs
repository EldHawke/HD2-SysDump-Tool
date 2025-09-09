using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using Vanara.PInvoke;
using static Vanara.PInvoke.DbgHelp;

namespace HD2_TS_Tool
{
    public partial class Form1 : Form
    {
        public static string GamePath;
        public Form1()
        {
            InitializeComponent();
        }

        /*--------------sys info section - begin--------------*/
        private async void sysinfo_Click(object sender, EventArgs e)
        {
            // Show panel
            progPanel.Visible = true;
            progressBar1.Minimum = 0;
            progressBar1.Maximum = 100;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                Report(0, "Getting GPU info...");
                string gpu = GetGPUs();

                Report(20, "Getting OS info...");
                string os = GetOSInfo();

                Report(40, "Getting CPU info...");
                string cpu = GetCPU();

                Report(60, "Getting disk info...");
                string disks = GetDisks();

                Report(80, "Getting RAM info...");
                string ram = GetRAM();

                Report(90, "Getting Hotfixes...");
                string[] kbs = { "KB5063878", "KB5063709" };
                string hotfixes = GetHotfixes(kbs);

                Report(100, "Done!");

                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = $"{gpu}\n{os}\n{cpu}\n{disks}\n{ram}\n{hotfixes}";
                    progPanel.Visible = false; // hide panel when done
                }));
            });

        }

        public static string GetGPUs()
        {
            var sb = new System.Text.StringBuilder("==== GPU Adapters ====\n");

            using (var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT DeviceName, DriverVersion, DeviceClass FROM Win32_PnPSignedDriver WHERE DeviceClass='DISPLAY'"))
            {
                foreach (System.Management.ManagementObject gpu in searcher.Get())
                {
                    string name = gpu["DeviceName"]?.ToString() ?? "Unknown";
                    string drv = gpu["DriverVersion"]?.ToString() ?? "Unknown";
                    string mkt = null;

                    if (name.Contains("NVIDIA"))
                    {
                        mkt = GetNvidiaVersion() ?? ParseDriverVersion(drv);
                    }
                    else if (name.Contains("AMD"))
                    {
                        mkt = (string)Microsoft.Win32.Registry.GetValue(
                                  @"HKEY_LOCAL_MACHINE\SOFTWARE\AMD\CN", "DriverVersion", null)
                              ?? (string)Microsoft.Win32.Registry.GetValue(
                                  @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\AMD\CN", "DriverVersion", null)
                              ?? drv;
                    }
                    else if (name.Contains("Intel"))
                    {
                        mkt = drv;
                    }

                    if (mkt == null) mkt = drv;

                    sb.AppendLine(string.Format("{0} | {1} | {2}", name, drv, mkt));
                }
            }

            return sb.ToString();
        }

        // NVIDIA helper moved outside
        private static string GetNvidiaVersion()
        {
            return (string)Microsoft.Win32.Registry.GetValue(
                       @"HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Installer", "LastInstallerVersion", null)
                   ?? (string)Microsoft.Win32.Registry.GetValue(
                       @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\NVIDIA Corporation\Installer", "LastInstallerVersion", null)
                   ?? (string)Microsoft.Win32.Registry.GetValue(
                       @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm", "DriverVersion", null);
        }

        // Fallback parsing moved outside
        private static string ParseDriverVersion(string drv)
        {
            if (drv == null) return null;
            var parts = drv.Split('.');
            if (parts.Length < 4) return null;

            string concat = parts[2] + parts[3];
            if (concat.Length == 6 && concat.StartsWith("1")) concat = concat.Substring(1);

            ulong dummy;
            if (ulong.TryParse(concat, out dummy))
            {
                string firstPart = concat.Substring(0, concat.Length - 2);
                string lastPart = concat.Substring(concat.Length - 2, 2);
                return firstPart + "." + lastPart;
            }

            return null;
        }

        public static string GetOSInfo()
        {
            string result = "==== OS ====\n";

            using (var searcher = new ManagementObjectSearcher("SELECT Caption, Version, BuildNumber, OSArchitecture FROM Win32_OperatingSystem"))
            {
                foreach (ManagementObject os in searcher.Get())
                {
                    string caption = os["Caption"]?.ToString();
                    string version = os["Version"]?.ToString();
                    string build = os["BuildNumber"]?.ToString();
                    string arch = os["OSArchitecture"]?.ToString();

                    result += $"{caption} | Version {version} | Build {build} | {arch}\n";
                }
            }

            return result;
        }

        public static string GetCPU()
        {
            string result = "==== CPU ====\n";

            using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor"))
            {
                foreach (ManagementObject cpu in searcher.Get())
                {
                    result += $"{cpu["Name"]}\n";
                }
            }

            return result;
        }

        public static string GetDisks()
        {
            var sb = new System.Text.StringBuilder("==== Disks ====\n");

            try
            {
                var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT Model, Size, InterfaceType, PNPDeviceID FROM Win32_DiskDrive");

                foreach (System.Management.ManagementObject disk in searcher.Get())
                {
                    string name = disk["Model"]?.ToString() ?? "Unknown";
                    ulong sizeBytes = (disk["Size"] != null) ? (ulong)disk["Size"] : 0;
                    double sizeGB = Math.Round(sizeBytes / 1024.0 / 1024 / 1024, 0);

                    string busType = disk["InterfaceType"]?.ToString() ?? "Unknown";

                    // NVMe detection
                    string pnpId = disk["PNPDeviceID"]?.ToString() ?? "";
                    if (pnpId.IndexOf("NVMe", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        busType = "NVMe";
                    }

                    sb.AppendLine(string.Format("{0} | {1} GB | {2}", name, sizeGB, busType));
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("Error retrieving disks: " + ex.Message);
            }

            return sb.ToString();
        }

        public static string GetRAM()
        {
            string result = "==== RAM ====\n";
            double totalGb = 0;

            using (var searcher = new ManagementObjectSearcher("SELECT Manufacturer, Capacity, Speed FROM Win32_PhysicalMemory"))
            {
                foreach (ManagementObject mem in searcher.Get())
                {
                    string manufacturer = mem["Manufacturer"]?.ToString();
                    double sizeGb = mem["Capacity"] != null ? Math.Round(Convert.ToDouble(mem["Capacity"]) / (1024 * 1024 * 1024)) : 0;
                    totalGb += sizeGb;
                    string speed = mem["Speed"]?.ToString();

                    result += $"{manufacturer} | {sizeGb} GB | {speed} MHz\n";
                }
            }

            result += $"Total RAM: {Math.Round(totalGb)} GB\n";
            return result;
        }

        public static string GetHotfixes(string[] kbIds)
        {
            string result = "==== Specific Hotfix Check ====\n";

            using (var searcher = new ManagementObjectSearcher("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering"))
            {
                foreach (ManagementObject hotfix in searcher.Get())
                {
                    string id = hotfix["HotFixID"]?.ToString();
                    if (Array.Exists(kbIds, kb => kb.Equals(id, StringComparison.OrdinalIgnoreCase)))
                    {
                        string desc = hotfix["Description"]?.ToString();
                        string date = hotfix["InstalledOn"]?.ToString();
                        result += $"{id} {desc} {date}\n";
                    }
                }
            }

            return result;
        }

        /*--------------sys info section - end--------------*/

        //-----------

        /*--------------dmp reading section - begin--------------*/

        private async void readdumps_Click(object sender, EventArgs e)
        {
            // Show panel
            progPanel.Visible = true;
            progressBar1.Minimum = 0;
            progressBar1.Maximum = 100;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                string reportsFolder = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Arrowhead", "Helldivers2", "crash_data", "reports");

                Report(20, "Reading dump files...");
                string result = ParseLatestDump(reportsFolder); // your static parsing function

                Report(100, "Done!");

                // Update RichTextBox on UI thread
                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = result;
                    progPanel.Visible = false; // hide panel when finished
                }));
            });
        }

        public static string ParseLatestDump(string reportsFolder)
        {

            if (!Directory.Exists(reportsFolder))
                return $"Reports folder not found: {reportsFolder}\n";

            var latestDump = new DirectoryInfo(reportsFolder)
                .GetFiles("*.dmp")
                .OrderByDescending(f => f.LastWriteTime)
                .FirstOrDefault();

            if (latestDump == null)
                return $"No .dmp file found in {reportsFolder}\n";

            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"Latest dump: {latestDump.Name}");
            sb.AppendLine($"OS Version: {Environment.OSVersion}");

            try
            {
                byte[] dumpBytes = File.ReadAllBytes(latestDump.FullName);
                IntPtr basePtr = Marshal.UnsafeAddrOfPinnedArrayElement(dumpBytes, 0);

                if (MiniDumpReadDumpStream(basePtr, (uint)MINIDUMP_STREAM_TYPE.ExceptionStream,
                    out IntPtr dirPtr, out IntPtr streamPtr, out uint streamSize))
                {
                    var excStream = Marshal.PtrToStructure<MINIDUMP_EXCEPTION_STREAM>(streamPtr);

                    sb.AppendLine($"Exception Code: 0x{excStream.ExceptionRecord.ExceptionCode:X}");
                    sb.AppendLine($"Exception Address: 0x{excStream.ExceptionRecord.ExceptionAddress:X}");

                    // Look for ASCII keywords
                    string text = Encoding.ASCII.GetString(dumpBytes);
                    var matches = Regex.Matches(text, @"[ -~]{4,}");
                    foreach (Match m in matches)
                    {
                        if (Regex.IsMatch(m.Value, "error|exception|failed", RegexOptions.IgnoreCase))
                            sb.AppendLine("  " + m.Value);
                    }
                }
                else
                {
                    sb.AppendLine("No exception stream found.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"Failed to read dump: {ex.Message}");
            }

            return sb.ToString();
        }

        /*--------------dmp reading section - end--------------*/

        //-----------

        /*--------------general checks section - begin--------------*/

        private async void genchecks_Click(object sender, EventArgs e)
        {
            // Show progress panel
            progPanel.Visible = true;
            progressBar1.Minimum = 0;
            progressBar1.Maximum = 100;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                string result = "";

                // Helper to report progress
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                var checks = new (Func<string> func, string name)[]
                {
                    (CheckRebootPending, "Checking reboot pending"),
                    (RunCPUCheck, "Running CPU check"),
                    (CheckPageFile, "Checking page file"),
                    (CheckSystemClock, "Checking system clock"),
                    (RunPrinterCheck, "Running printer check"),
                    (() => CheckLongSystemUptime(), "Checking system uptime"), // wrap in lambda
                    (CheckAvx2Support, "Checking AVX2 support"),
                    (CheckMemoryConfiguration, "Checking memory configuration"),
                    (CheckDomainResolution, "Checking domain resolution"),
                    (CheckFirewallRules, "Checking firewall rules"),
                    (() => CheckHelldivers2InstallAndLaunchOptions(), "Checking Helldivers2 install & launch options"), // wrap in lambda
                    (FindMods, "Finding mods"),
                    (CheckSecureBoot, "Checking Secure Boot"),
                    (TestDoubleNAT, "Testing double NAT")
                };

                int total = checks.Length;
                for (int i = 0; i < total; i++)
                {
                    Report((i * 100) / total, checks[i].name);
                    string output = checks[i].func();
                    result += output + "\n";
                }

                Report(100, "Done!");

                // Update UI
                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = result;
                    moreopts.Visible = true;
                    progPanel.Visible = false;
                }));
            });
        }

        public static string CheckRebootPending()
        {
            StringBuilder sb = new StringBuilder();
            bool pending = false;

            sb.AppendLine("==== Reboot Status Check ====");

            // CBS RebootPending
            using (var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
            {
                if (key != null)
                {
                    pending = true;
                    sb.AppendLine("CBS: RebootPending flag present");
                }
            }

            // Windows Update
            using (var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
            {
                if (key != null)
                {
                    pending = true;
                    sb.AppendLine("Windows Update: RebootRequired flag present");
                }
            }

            // Pending file rename operations
            using (var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager"))
            {
                if (key?.GetValue("PendingFileRenameOperations") is string[] ops && ops.Length > 0)
                {
                    pending = true;
                    sb.AppendLine($"Pending file operations: {ops.Length} entries (not listed)");
                }
            }

            // Final recommendation
            if (pending)
            {
                sb.AppendLine();
                sb.AppendLine("⚠️ Recommended Action: Please reboot Windows to complete updates/installs.");
            }
            else
            {
                sb.AppendLine("✅ No reboot required at this time.");
            }

            return sb.ToString();
        }

        private static readonly string[] AffectedModels = new[]
        {
            "13900", "13790", "13700", "13600", "13500", "13490", "13400",
            "14900", "14790", "14700", "14600", "14500", "14490", "14400"
        };

        // Latest known safe microcode versions (hex strings, e.g. 0x12F)
        private static readonly string[] LatestMicrocode = new[]
        {
        "0x12F", "0x3A"
        };

        public static string RunCPUCheck()
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                string cpuName = GetCpuName();
                string microcode = GetCpuMicrocodeVersion();

                sb.AppendLine("==== Intel Microcode Check ====");
                sb.AppendLine($"Detected CPU: {cpuName}");
                sb.AppendLine($"Detected Microcode: {microcode}");

                if (string.IsNullOrEmpty(cpuName) || string.IsNullOrEmpty(microcode))
                {
                    sb.AppendLine();
                    sb.AppendLine("❌ Error determining CPU microcode version.");
                    return sb.ToString();
                }

                bool isAffected = AffectedModels.Any(m => cpuName.Contains(m));
                bool isSafe = LatestMicrocode.Contains(microcode, StringComparer.OrdinalIgnoreCase);

                if (isAffected && !isSafe)
                {
                    sb.AppendLine();
                    sb.AppendLine("❌ [FAIL] CPU model with unpatched microcode detected!!");
                    sb.AppendLine("⚠️ WARNING: Update your motherboard UEFI (BIOS) ASAP to prevent permanent CPU damage.");
                    sb.AppendLine("If you are experiencing stability issues, your CPU may already be unstable/damaged.");
                    sb.AppendLine("More info: https://www.theverge.com/2024/7/26/24206529/intel-13th-14th-gen-crashing-instability-cpu-voltage-q-a");
                }
                else if (isAffected && isSafe)
                {
                    sb.AppendLine();
                    sb.AppendLine($"✅ Your CPU is running the latest microcode ({microcode}).");
                }
                else
                {
                    sb.AppendLine();
                    sb.AppendLine("✅ This CPU model is not affected by the Intel microcode issue.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("❌ Error occurred while running Intel Microcode check.");
                sb.AppendLine(ex.Message);
            }

            return sb.ToString();
        }

        private static string GetCpuName()
        {
            using (var searcher = new ManagementObjectSearcher("select Name from Win32_Processor"))
            {
                foreach (var item in searcher.Get())
                {
                    return item["Name"]?.ToString() ?? string.Empty;
                }
            }
            return string.Empty;
        }

        private static string GetCpuMicrocodeVersion()
        {
            // Microcode version isn't directly exposed via WMI, but Windows stores it under the registry:
            // HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0\Update Revision
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
            {
                if (key?.GetValue("Update Revision") is byte[] raw && raw.Length >= 4)
                {
                    uint revision = BitConverter.ToUInt32(raw, 0);
                    return "0x" + revision.ToString("X");
                }
            }
            return string.Empty;
        }

        public static string CheckPageFile()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Page File Check ====");

            try
            {
                // Registry key for page file config
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"))
                {
                    if (key != null)
                    {
                        object value = key.GetValue("PagingFiles");
                        if (value is string[] pagingFiles && pagingFiles.Length > 0)
                        {
                            // Example entry: "C:\pagefile.sys 0 0" (zero = disabled)
                            bool disabled = pagingFiles.All(p => p.Contains(" 0 0"));

                            if (disabled)
                            {
                                sb.AppendLine("⚠️ Your page file is set to zero. This may cause the game to crash on launch.");
                            }
                            else
                            {
                                sb.AppendLine("✅ Page file appears to be enabled.");
                            }
                        }
                        else
                        {
                            sb.AppendLine("⚠️ Could not read page file settings.");
                        }
                    }
                    else
                    {
                        sb.AppendLine("⚠️ Registry key not found for page file settings.");
                    }
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error checking page file: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string CheckSystemClock()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== System Clock Check ====");

            try
            {
                DateTime localNow = DateTime.Now;
                DateTime utcNow = DateTime.UtcNow;
                TimeSpan diff = localNow - utcNow;

                // Rough sanity check: local offset should match the system timezone offset
                TimeSpan expectedOffset = TimeZoneInfo.Local.GetUtcOffset(DateTime.UtcNow);

                if (Math.Abs((diff - expectedOffset).TotalMinutes) > 5)
                {
                    sb.AppendLine("❌ Your time and/or date is inaccurate. This will cause connection issues.");
                }
                else
                {
                    sb.AppendLine("✅ System clock appears accurate.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error checking system clock: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string RunPrinterCheck()
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                sb.AppendLine("==== Bad Printer Check ====");

                bool found = false;
                using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Printer"))
                {
                    foreach (var printer in searcher.Get())
                    {
                        string name = printer["Name"]?.ToString() ?? string.Empty;
                        if (name.IndexOf("OneNote", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            found = true;
                            sb.AppendLine("❌ [FAIL] OneNote for Windows 10 virtual printer detected!");
                            sb.AppendLine("⚠️ This can cause crashes on game startup.");
                            sb.AppendLine("Please remove this printer driver from your computer.");
                            sb.AppendLine("Opening Printers window...");

                            Process.Start("explorer.exe", "shell:PrintersFolder");
                            break;
                        }
                    }
                }

                if (!found)
                {
                    sb.AppendLine("✅ No problematic OneNote virtual printer found.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("❌ Error occurred while checking printers.");
                sb.AppendLine(ex.Message);
            }

            return sb.ToString();
        }

        public static string CheckLongSystemUptime(int maxDays = 7)
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                sb.AppendLine("==== System Uptime Check (7 Days) ====");
                // Environment.TickCount64 gives uptime in milliseconds
                var uptime = TimeSpan.FromMilliseconds(Environment.TickCount);
                int uptimeDays = (int)uptime.TotalDays;

                if (uptimeDays > maxDays)
                {
                    sb.AppendLine($"❌ Your computer has not been restarted in {uptimeDays} days.\n" +
                           "Please restart your computer. Restart only. Do not use 'Shutdown'.\n");
                    return sb.ToString();
                }
                else
                {
                    sb.Append($"✅ System uptime is {uptimeDays} days — within normal range.\n");
                    return sb.ToString();
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Could not determine system uptime: {ex.Message}");
                return sb.ToString();
            }
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool IsProcessorFeaturePresent(uint ProcessorFeature);

        // PF_AVX2_INSTRUCTIONS_AVAILABLE = 40
        const uint PF_AVX2_INSTRUCTIONS_AVAILABLE = 40;

        public static string CheckAvx2Support()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== CPU AVX2 Support Check ====");

            try
            {
                bool hasAvx2 = IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE);

                if (!hasAvx2)
                {
                    sb.AppendLine("❌ Your CPU does not support the AVX2 instruction set.");
                }
                else
                {
                    sb.AppendLine("✅ CPU supports the AVX2 instruction set.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Could not determine AVX2 support: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string CheckMemoryConfiguration()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Memory Configuration Check ====");

            try
            {
                var searcher = new ManagementObjectSearcher("SELECT Manufacturer, Capacity, Speed, PartNumber, DeviceLocator FROM Win32_PhysicalMemory");
                var modules = searcher.Get().Cast<ManagementObject>().ToList();

                if (!modules.Any())
                {
                    sb.AppendLine("⚠️ RAM Information not found.");
                    return sb.ToString();
                }

                // Gather details
                var ramInfo = modules.Select(m => new
                {
                    Manufacturer = m["Manufacturer"]?.ToString() ?? "Unknown",
                    CapacityGB = Math.Round(Convert.ToDouble(m["Capacity"]) / (1024 * 1024 * 1024), 0),
                    Speed = m["Speed"]?.ToString() ?? "Unknown",
                    PartNumber = m["PartNumber"]?.ToString() ?? "Unknown",
                    Slot = m["DeviceLocator"]?.ToString() ?? "Unknown"
                }).ToList();

                // Check matching
                bool allSame = ramInfo.All(r =>
                    r.CapacityGB == ramInfo.First().CapacityGB &&
                    r.Speed == ramInfo.First().Speed &&
                    r.Manufacturer == ramInfo.First().Manufacturer);

                if (!allSame && ramInfo.Count > 1)
                {
                    sb.AppendLine("❌ You have mixed memory. This can cause performance and stability issues.");
                }
                else
                {
                    sb.AppendLine("✅ All installed RAM modules match.");
                }

                // Check multi-channel by count
                if (ramInfo.Count == 1)
                {
                    sb.AppendLine("❌ Memory running in single-channel mode. This will hurt performance.");
                }
                else
                {
                    sb.AppendLine("✅ Multiple RAM sticks detected — likely running in dual/quad channel.");
                }

                // Memory speed (effective DDR = Speed * 2)
                int speed;
                if (int.TryParse(ramInfo.First().Speed, out speed))
                {
                    sb.AppendLine($"ℹ️ RAM is currently running at {speed * 2} MHz (DDR effective).");
                }
                else
                {
                    sb.AppendLine("⚠️ RAM speed not found.");
                }

                // Always display a RAM info table
                sb.AppendLine();
                sb.AppendLine("RAM Information:");
                foreach (var r in ramInfo)
                {
                    sb.AppendLine($"   Slot: {r.Slot} | {r.Manufacturer} | {r.CapacityGB} GB | {r.Speed} MHz | {r.PartNumber}");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error occurred while checking RAM: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string CheckDomainResolution()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Domain Resolution Check ====");

            var requiredDomains = new List<string>
        {
            "akamaihd.net",
            "api.live.prod.thehelldiversgame.com",
            "cluster-a.playfabapi.com",
            "gameguard.co.kr",
            "gameguard.thehelldiversgame.com",
            "mgr.gameguard.co.kr",
            "ocsp.digicert.com",
            "playfabapi.com",
            "pss-cloud.net",
            "steamcommunity.com",
            "steamcontent.com",
            "steamgames.com",
            "steampowered.com",
            "steamstatic.com",
            "steamusercontent.com",
            "testament.api.wwsga.me"
        };

            List<string> failedDomains = new List<string>();

            foreach (var domain in requiredDomains)
            {
                try
                {
                    Dns.GetHostEntry(domain); // test DNS resolution
                    sb.AppendLine($"✅ {domain} resolved successfully.");
                }
                catch
                {
                    failedDomains.Add(domain);
                }
            }

            if (failedDomains.Count > 0)
            {
                sb.AppendLine("❌ The following URLs failed to resolve with DNS:");
                foreach (var d in failedDomains)
                    sb.AppendLine($"   - {d}");
            }

            return sb.ToString();
        }

        public static string CheckFirewallRules()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Firewall Rules Check ====");

            // Run netsh to list all firewall rules for HELLDIVERS™ 2
            string firewallOutput = RunCommand("netsh", "advfirewall firewall show rule name=\"HELLDIVERS™ 2\"");

            bool hasTcp = Regex.IsMatch(firewallOutput, @"Protocol\s*:\s*TCP", RegexOptions.IgnoreCase);
            bool hasUdp = Regex.IsMatch(firewallOutput, @"Protocol\s*:\s*UDP", RegexOptions.IgnoreCase);

            if (hasTcp)
                sb.AppendLine("✅ HELLDIVERS™ 2 inbound TCP rule found.");
            else
                sb.AppendLine("❌ Missing HELLDIVERS™ 2 inbound TCP rule.");

            if (hasUdp)
                sb.AppendLine("✅ HELLDIVERS™ 2 inbound UDP rule found.");
            else
                sb.AppendLine("❌ Missing HELLDIVERS™ 2 inbound UDP rule.");

            // If either is missing, open firewall settings
            if (!hasTcp || !hasUdp)
            {
                sb.AppendLine("⚠️ Please add the missing rules manually in Windows Firewall.");
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "wf.msc",
                        UseShellExecute = true
                    });
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"⚠️ Could not open Firewall settings: {ex.Message}");
                }
            }

            return sb.ToString();
        }

        private static string RunCommand(string fileName, string arguments)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (var proc = Process.Start(psi))
            {
                return proc.StandardOutput.ReadToEnd();
            }
        }

        public static string CheckHelldivers2InstallAndLaunchOptions(string steamPath = @"C:\Program Files (x86)\Steam")
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Helldivers 2 Install & Launch Options Check ====");

            string gamePath = null;

            try
            {
                // STEP 1: Locate Steam libraries
                string libraryFoldersVdf = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
                if (!File.Exists(libraryFoldersVdf))
                {
                    sb.AppendLine("❌ Could not find libraryfolders.vdf. Is Steam installed?");
                    return sb.ToString();
                }

                string content = File.ReadAllText(libraryFoldersVdf);

                // Regex to capture all Steam library paths
                var matches = Regex.Matches(content, "\"path\"\\s*\"([^\"]+)\"");
                List<string> libraryPaths = new List<string>();

                foreach (Match m in matches)
                {
                    if (m.Groups.Count > 1)
                        libraryPaths.Add(m.Groups[1].Value.Replace(@"\\", @"\"));
                }

                // Always include default Steam path
                libraryPaths.Add(steamPath);

                // STEP 2: Find appmanifest_553850.acf
                foreach (var libPath in libraryPaths.Distinct())
                {
                    string manifestPath = Path.Combine(libPath, "steamapps", "appmanifest_553850.acf");
                    if (File.Exists(manifestPath))
                    {
                        string manifestContent = File.ReadAllText(manifestPath);
                        var dirMatch = Regex.Match(manifestContent, "\"installdir\"\\s*\"([^\"]+)\"");
                        if (dirMatch.Success)
                        {
                            string installDirName = dirMatch.Groups[1].Value;
                            gamePath = Path.Combine(libPath, "steamapps", "common", installDirName);

                            if (Directory.Exists(gamePath))
                            {
                                sb.AppendLine($"✅ Helldivers 2 found at: {gamePath}");
                                GamePath = gamePath;
                            }
                            else
                            {
                                sb.AppendLine($"❌ Install dir from manifest not found on disk: {gamePath}");
                            }
                        }
                    }
                }

                if (gamePath == null)
                {
                    sb.AppendLine("❌ Helldivers 2 not found in any Steam library.");
                    return sb.ToString();
                }

                // STEP 3: Get Launch Options from localconfig.vdf
                string userDataDir = Path.Combine(steamPath, "userdata");
                if (Directory.Exists(userDataDir))
                {
                    var profileDirs = Directory.GetDirectories(userDataDir);
                    string latestProfile = profileDirs.OrderByDescending(Directory.GetLastWriteTime).FirstOrDefault();

                    if (latestProfile != null)
                    {
                        string localConfigPath = Path.Combine(latestProfile, "config", "localconfig.vdf");
                        if (File.Exists(localConfigPath))
                        {
                            string localConfigContent = File.ReadAllText(localConfigPath);
                            var regex = new Regex("(?sm)\"553850\"\\s*\\{(?:[^{}]|(?<open>\\{)|(?<-open>\\}))*?(?(open)(?!))[^}]*?\"LaunchOptions\"\\s*\"([^\"]*)\"");
                            var match = regex.Match(localConfigContent);

                            if (match.Success)
                            {
                                string launchOptions = match.Groups[1].Value;
                                if (!string.IsNullOrWhiteSpace(launchOptions))
                                {
                                    sb.AppendLine($"🎮 Launch Options: {launchOptions}");
                                }
                                else
                                {
                                    sb.AppendLine("ℹ️ No launch options currently in use.");
                                }
                            }
                            else
                            {
                                sb.AppendLine("ℹ️ No LaunchOptions entry found for Helldivers 2.");
                            }
                        }
                        else
                        {
                            sb.AppendLine("⚠️ localconfig.vdf not found in Steam userdata.");
                        }
                    }
                }
                else
                {
                    sb.AppendLine("⚠️ Could not find Steam userdata folder.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string FindMods()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Mod Detection Check ====");

            if (string.IsNullOrEmpty(GamePath) || !Directory.Exists(GamePath))
            {
                sb.AppendLine("ℹ️ Helldivers 2 not found. Skipping mod detection.");
                return sb.ToString();
            }

            string dataDir = Path.Combine(GamePath, "data");
            if (!Directory.Exists(dataDir))
            {
                sb.AppendLine("⚠️ Data folder not found.");
                return sb.ToString();
            }

            try
            {
                var patchFiles = Directory.GetFiles(dataDir, "*.patch_*", SearchOption.TopDirectoryOnly);
                if (patchFiles.Length == 0)
                {
                    sb.AppendLine("✅ No mods detected.");
                }
                else
                {
                    sb.AppendLine("❌ Mods detected:");
                    foreach (var file in patchFiles)
                        sb.AppendLine("   - " + Path.GetFileName(file));
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error scanning for mods: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string CheckSecureBoot()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Secure Boot Check ====");

            try
            {
                // Step 1: Check firmware type (UEFI or Legacy BIOS)
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        string firmwareType = obj["SystemType"]?.ToString() ?? "Unknown";
                        if (firmwareType.IndexOf("EFI", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            sb.AppendLine("ℹ️ System is running in UEFI mode.");
                        }
                        else
                        {
                            sb.AppendLine("⚠️ System is running in Legacy BIOS mode. Secure Boot is not available.");
                            return sb.ToString(); // No need to check further
                        }
                    }
                }

                // Step 2: Query Secure Boot status (only works if UEFI)
                using (var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\HardwareManagement",
                    "SELECT SecureBootEnabled FROM MS_SecureBoot"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        bool enabled = (bool)obj["SecureBootEnabled"];
                        if (enabled)
                        {
                            sb.AppendLine("✅ Secure Boot is enabled.");
                        }
                        else
                        {
                            sb.AppendLine("❌ Secure Boot is disabled! Can cause GameGuard errors & disables Above 4G Decoding/Nvidia ReBAR/AMD SAM on Windows 11.");
                        }
                        return sb.ToString();
                    }
                }

                // Step 3: If nothing found
                sb.AppendLine("⚠️ Secure Boot information not available. Platform may not support it.");
            }
            catch (ManagementException mex) when (mex.ErrorCode == ManagementStatus.InvalidClass)
            {
                sb.AppendLine("⚠️ Secure Boot WMI class not available on this system. Likely not supported.");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error checking Secure Boot: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestDoubleNAT()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Double-NAT Test ====");

            try
            {
                string server = "cloudflare.com";
                IPAddress[] addresses = Dns.GetHostAddresses(server);
                if (addresses.Length == 0)
                {
                    sb.AppendLine("❌ Could not resolve Cloudflare.");
                    return sb.ToString();
                }

                IPAddress target = addresses[0];
                sb.AppendLine($"ℹ️ Target: {server} ({target})");

                List<IPAddress> privateIPs = new List<IPAddress>();
                int maxHops = 10;
                int timeout = 3000;

                using (Ping ping = new Ping())
                {
                    for (int ttl = 1; ttl <= maxHops; ttl++)
                    {
                        PingOptions options = new PingOptions(ttl, true);
                        byte[] buffer = new byte[32];
                        PingReply reply = ping.Send(target, timeout, buffer, options);

                        if (reply?.Address != null)
                        {
                            IPAddress hopIP = reply.Address;
                            if (IsPrivateIP(hopIP))
                                privateIPs.Add(hopIP);

                            if (reply.Status == IPStatus.Success)
                                break;
                        }
                    }
                }

                if (privateIPs.Count > 1)
                {
                    sb.AppendLine("⚠️ Possible Double-NAT connection detected.");
                    sb.AppendLine("Private IPs detected are:");
                    foreach (var ip in privateIPs.Distinct())
                        sb.AppendLine(" - " + ip);

                    sb.AppendLine("ℹ️ If you're not sure what these results mean, they are safe to share with others.");
                }
                else
                {
                    sb.AppendLine("✅ No Double-NAT connection detected.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error during Double-NAT test: {ex.Message}");
            }

            return sb.ToString();
        }

        private static bool IsPrivateIP(IPAddress ip)
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                byte[] bytes = ip.GetAddressBytes();
                // 10.0.0.0/8
                if (bytes[0] == 10) return true;
                // 172.16.0.0/12
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168) return true;
            }
            return false;
        }

        /*--------------general checks section - end--------------*/

        //-----------

        /*--------------network checks section - begin--------------*/

        private async void netchecks_Click(object sender, EventArgs e)
        {
            // Show progress panel
            progPanel.Visible = true;
            progressBar1.Minimum = 0;
            progressBar1.Maximum = 100;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                string result = "";

                // Helper to report progress
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                var checks = new (Func<string> func, string name)[]
                {
                    (() => TestLatency(), "Testing latency"),
                    (TestProxy, "Testing proxy"),
                    (TestVPN, "Testing VPN"),
                    (TestDownloadSpeed, "Testing download speed"),
                    (() => TestPort(), "Testing port"),
                    (TestNATType, "Testing NAT type"),
                    (() => TestMTU(), "Testing MTU"),
                    (() => TestTraceRoute(), "Tracing route"),
                    (() => TestPacketLoss(), "Testing packet loss"),
                    (() => TestTCPHandshake(), "Testing TCP handshake"),
                    (() => TestNetworkStability(), "Testing network stability")
                };

                int total = checks.Length;
                for (int i = 0; i < total; i++)
                {
                    Report((i * 100) / total, checks[i].name);
                    string output = checks[i].func(); // wrap with lambda if signature differs
                    result += output + "\n";
                }

                Report(100, "Done!");

                // Update UI
                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = result;
                    progPanel.Visible = false;
                }));
            });
        }

        public static string TestLatency(string host = "cloudflare.com", int attempts = 4)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Latency & Jitter Test ====");

            try
            {
                IPAddress[] addresses = Dns.GetHostAddresses(host);
                if (addresses.Length == 0)
                {
                    sb.AppendLine("❌ Could not resolve host.");
                    return sb.ToString();
                }

                IPAddress target = addresses[0];
                sb.AppendLine($"ℹ️ Target: {host} ({target})");

                List<long> rtts = new List<long>();
                using (Ping ping = new Ping())
                {
                    for (int i = 0; i < attempts; i++)
                    {
                        PingReply reply = ping.Send(target, 3000);
                        if (reply.Status == IPStatus.Success)
                        {
                            sb.AppendLine($"📶 Reply {i + 1}: {reply.RoundtripTime} ms");
                            rtts.Add(reply.RoundtripTime);
                        }
                        else
                        {
                            sb.AppendLine($"❌ Reply {i + 1}: {reply.Status}");
                        }
                    }
                }

                if (rtts.Count > 0)
                {
                    double avg = rtts.Average();
                    double jitter = rtts.Count > 1 ? rtts.Select((t, idx) => idx == 0 ? 0 : Math.Abs(t - rtts[idx - 1])).Average() : 0;
                    sb.AppendLine($"ℹ️ Average latency: {avg:F1} ms");
                    sb.AppendLine($"ℹ️ Approx. jitter: {jitter:F1} ms");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error during latency test: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestProxy()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Proxy Detection ====");

            try
            {
                var proxy = WebRequest.DefaultWebProxy;
                Uri testUri = new Uri("https://google.com");

                if (proxy != null)
                {
                    Uri proxyUri = proxy.GetProxy(testUri);
                    if (proxyUri != null && proxyUri != testUri)
                    {
                        sb.AppendLine($"⚠️ Proxy in use: {proxyUri}");
                    }
                    else
                    {
                        sb.AppendLine("✅ No active proxy detected.");
                    }
                }
                else
                {
                    sb.AppendLine("✅ No proxy detected.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error detecting proxy: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestVPN()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== VPN Detection ====");

            try
            {
                string publicIP;
                using (var wc = new WebClient())
                {
                    publicIP = wc.DownloadString("https://api.ipify.org").Trim();
                }

                var localIPs = Dns.GetHostAddresses(Dns.GetHostName())
                                  .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                                  .Select(ip => ip.ToString())
                                  .ToList();

                sb.AppendLine($"ℹ️ Public IP: {publicIP}");
                sb.AppendLine("ℹ️ Local IPs:");
                foreach (var ip in localIPs) sb.AppendLine(" - " + ip);

                if (!localIPs.Contains(publicIP))
                    sb.AppendLine("⚠️ VPN or tunnel may be active (public IP differs from local IPs). - WARNING: Could be false positive!");
                else
                    sb.AppendLine("✅ No VPN detected (public IP matches local IP). - WARNING: This device is exposed directly to the internet!");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error detecting VPN: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestDownloadSpeed()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Download Speed Test ====");

            try
            {
                // Force TLS 1.2 and ignore SSL certificate validation
                System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                System.Net.ServicePointManager.ServerCertificateValidationCallback =
                    (sender, cert, chain, sslPolicyErrors) => true;

                string url = "https://fsn1-speed.hetzner.com/100MB.bin";

                using (var wc = new WebClient())
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    byte[] data = wc.DownloadData(url);  // synchronous
                    sw.Stop();

                    double seconds = sw.Elapsed.TotalSeconds;
                    double mb = data.Length / (1024.0 * 1024.0);
                    double speed = mb / seconds;

                    sb.AppendLine($"ℹ️ Downloaded {mb:F2} MB in {seconds:F2} s");
                    sb.AppendLine($"ℹ️ Approx. speed: {speed:F2} MB/s");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error during download test: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestPort(string host = "cloudflare.com", int port = 443)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"==== Port {port} Test ====");

            try
            {
                using (var client = new TcpClient())
                {
                    var task = client.ConnectAsync(host, port);
                    if (task.Wait(3000))
                        sb.AppendLine($"✅ Port {port} is open on {host}");
                    else
                        sb.AppendLine($"❌ Port {port} is not reachable on {host}");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error testing port {port}: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestNATType()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== NAT Type Detection ====");

            try
            {
                // Using UDP to STUN server (public STUN server example)
                string stunServer = "stun.l.google.com";
                int stunPort = 19302;

                using (UdpClient client = new UdpClient(0)) // bind to random local port
                {
                    client.Client.ReceiveTimeout = 3000;
                    var endpoint = new IPEndPoint(Dns.GetHostAddresses(stunServer)[0], stunPort);

                    // Minimal STUN binding request
                    byte[] request = new byte[20];
                    request[0] = 0; request[1] = 1; // binding request
                    client.Send(request, request.Length, endpoint);

                    var received = client.Receive(ref endpoint);

                    sb.AppendLine($"✅ STUN server responded ({received.Length} bytes)");
                    sb.AppendLine("ℹ️ NAT type detection requires full STUN parsing; for now, basic response indicates a NAT exists.");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error during NAT test: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestMTU(string host = "8.8.8.8")
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== MTU / Fragmentation Test ====");

            try
            {
                int min = 500, max = 1500, mtu = min;
                using (Ping ping = new Ping())
                {
                    while (min <= max)
                    {
                        int size = (min + max) / 2;
                        PingOptions options = new PingOptions(64, true); // do not fragment
                        byte[] buffer = new byte[size];
                        var reply = ping.Send(host, 2000, buffer, options);

                        if (reply.Status == IPStatus.Success)
                        {
                            mtu = size;
                            min = size + 1;
                        }
                        else
                        {
                            max = size - 1;
                        }
                    }
                }
                sb.AppendLine($"ℹ️ Estimated MTU without fragmentation: {mtu} bytes");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error during MTU test: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestTraceRoute(string host = "cloudflare.com", int maxHops = 30)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Trace Route ====");

            try
            {
                IPAddress target = Dns.GetHostAddresses(host)[0];
                sb.AppendLine($"ℹ️ Target: {host} ({target})");

                using (Ping ping = new Ping())
                {
                    for (int ttl = 1; ttl <= maxHops; ttl++)
                    {
                        PingOptions options = new PingOptions(ttl, true);
                        byte[] buffer = new byte[32];
                        PingReply reply = ping.Send(target, 3000, buffer, options);

                        if (reply?.Address != null)
                        {
                            sb.AppendLine($"{ttl,2}: {reply.Address} ({reply.RoundtripTime} ms)");
                            if (reply.Status == IPStatus.Success) break;
                        }
                        else
                        {
                            sb.AppendLine($"{ttl,2}: *");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error during trace route: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestPacketLoss(string host = "8.8.8.8", int attempts = 20)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Packet Loss / Latency Spike Test ====");

            try
            {
                IPAddress target = Dns.GetHostAddresses(host)[0];
                int lost = 0;
                List<long> latencies = new List<long>();

                using (Ping ping = new Ping())
                {
                    for (int i = 0; i < attempts; i++)
                    {
                        PingReply reply = ping.Send(target, 2000);
                        if (reply.Status == IPStatus.Success)
                        {
                            sb.AppendLine($"📶 Reply {i + 1}: {reply.RoundtripTime} ms");
                            latencies.Add(reply.RoundtripTime);
                        }
                        else
                        {
                            sb.AppendLine($"❌ Reply {i + 1}: {reply.Status}");
                            lost++;
                        }
                    }
                }

                double lossPercent = (double)lost / attempts * 100;
                double avgLatency = latencies.Count > 0 ? latencies.Average() : 0;
                sb.AppendLine($"ℹ️ Packet loss: {lossPercent:F1}%");
                sb.AppendLine($"ℹ️ Average successful ping: {avgLatency:F1} ms");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error during packet loss test: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestTCPHandshake(string host = "cloudflare.com", int port = 443, int attempts = 5)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"==== TCP Handshake Timing Test ({host}:{port}) ====");

            try
            {
                List<long> connectTimes = new List<long>();

                for (int i = 0; i < attempts; i++)
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    using (TcpClient client = new TcpClient())
                    {
                        var task = client.ConnectAsync(host, port);
                        if (!task.Wait(3000)) sb.AppendLine($"❌ Attempt {i + 1}: Timeout");
                    }
                    sw.Stop();
                    sb.AppendLine($"📶 Attempt {i + 1}: {sw.ElapsedMilliseconds} ms");
                    connectTimes.Add(sw.ElapsedMilliseconds);
                }

                double avgTime = connectTimes.Average();
                double jitter = connectTimes.Count > 1
                    ? connectTimes.Select((t, idx) => idx == 0 ? 0 : Math.Abs(t - connectTimes[idx - 1])).Average()
                    : 0;

                sb.AppendLine($"ℹ️ Average handshake: {avgTime:F1} ms");
                sb.AppendLine($"ℹ️ Approx. handshake jitter: {jitter:F1} ms");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Error during TCP handshake test: {ex.Message}");
            }

            return sb.ToString();
        }

        public static string TestNetworkStability(string host = "8.8.8.8", int pingAttempts = 20, int tcpAttempts = 5, int tcpPort = 443)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== Network Stability Test ====");

            sb.AppendLine(TestPacketLoss(host, pingAttempts));
            sb.AppendLine(TestTCPHandshake(host, tcpPort, tcpAttempts));

            sb.AppendLine("ℹ️ Stability test completed. Check packet loss, latency spikes, and handshake jitter above.");
            return sb.ToString();
        }

        /*--------------network checks section - end--------------*/

        //-----------

        /*--------------one click functions section - begin--------------*/


        //set dns    
        private async void setdns_Click(object sender, EventArgs e)
        {
            // Create a simple dropdown popup dynamically
            var form = new Form()
            {
                Width = 400,
                Height = 150,
                Text = "Select Network Adapter",
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent
            };

            var combo = new ComboBox()
            {
                Left = 50,
                Top = 20,
                Width = 300,
                DropDownStyle = ComboBoxStyle.DropDownList
            };

            var okButton = new Button()
            {
                Text = "OK",
                Left = 150,
                Width = 100,
                Top = 60,
                DialogResult = DialogResult.OK
            };

            // Fill combo box with active adapters
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .ToList();

            foreach (var nic in adapters)
                combo.Items.Add(nic.Name);

            if (combo.Items.Count > 0) combo.SelectedIndex = 0;

            form.Controls.Add(combo);
            form.Controls.Add(okButton);
            form.AcceptButton = okButton;

            // Show the popup and exit if cancelled
            if (form.ShowDialog() != DialogResult.OK) return;

            string selectedAdapter = combo.SelectedItem.ToString();

            // Proceed with DNS setting using the selected adapter
            progPanel.Visible = true;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                Report(0, "Setting DNS...");

                // Pass the selected adapter to your static DNS method
                string dnsResult = SetActiveInterfaceDNS(selectedAdapter);

                Report(100, "Done!");

                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = dnsResult;
                    progPanel.Visible = false;
                }));
            });
        }
        //set dns
        public static string SetActiveInterfaceDNS(string adapterName)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("==== DNS Configuration via PowerShell ====");

            try
            {
                string psCommand = $@"
                $nic = Get-NetAdapter | Where-Object {{$_.Name -eq '{adapterName}' }}
                Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses ('1.1.1.1','8.8.8.8')
                Get-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex | ForEach-Object {{ $_.ServerAddresses }}
                ";

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{psCommand}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    Verb = "runas" // request admin
                };

                using (Process proc = new Process { StartInfo = psi })
                {
                    proc.Start();

                    while (!proc.StandardOutput.EndOfStream)
                        sb.AppendLine(proc.StandardOutput.ReadLine());

                    while (!proc.StandardError.EndOfStream)
                        sb.AppendLine("ERROR: " + proc.StandardError.ReadLine());

                    proc.WaitForExit();
                }

                sb.AppendLine("✅ DNS command finished.");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Exception: {ex.Message}");
            }

            return sb.ToString();
        }
        //wipe adapter
        private async void wipeadapter_Click(object sender, EventArgs e)
        {
            // Create a simple dropdown popup dynamically
            var form = new Form()
            {
                Width = 400,
                Height = 150,
                Text = "Select Network Adapter",
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent
            };

            var combo = new ComboBox()
            {
                Left = 50,
                Top = 20,
                Width = 300,
                DropDownStyle = ComboBoxStyle.DropDownList
            };

            var okButton = new Button()
            {
                Text = "OK",
                Left = 150,
                Width = 100,
                Top = 60,
                DialogResult = DialogResult.OK
            };

            // Fill combo box with active adapters
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .ToList();

            foreach (var nic in adapters)
                combo.Items.Add(nic.Name);

            if (combo.Items.Count > 0) combo.SelectedIndex = 0;

            form.Controls.Add(combo);
            form.Controls.Add(okButton);
            form.AcceptButton = okButton;

            // Show the popup and exit if cancelled
            if (form.ShowDialog() != DialogResult.OK) return;

            string selectedAdapter = combo.SelectedItem.ToString();

            // Proceed with DNS setting using the selected adapter
            progPanel.Visible = true;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                Report(0, "Wiping network settings...");

                // Pass the selected adapter to your static DNS method
                string dnsResult = ResetNetworkStack(selectedAdapter);

                Report(100, "Done!");

                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = dnsResult;
                    progPanel.Visible = false;
                }));
            });
        }
        //wipe adapter
        public static string ResetNetworkStack(string adapterName)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"==== Network Reset for {adapterName} ====");

            try
            {
                // PowerShell command to toggle adapter, set DHCP/IP/DNS
                string psCommand = $@"
            $nic = Get-NetAdapter | Where-Object {{$_.Name -eq '{adapterName}' }}
            Disable-NetAdapter -Name $nic.Name -Confirm:$false
            Enable-NetAdapter -Name $nic.Name -Confirm:$false
            # Set to DHCP and automatic DNS
            Set-NetIPInterface -InterfaceAlias $nic.Name -Dhcp Enabled
            Set-DnsClientServerAddress -InterfaceAlias $nic.Name -ResetServerAddresses
        ";

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{psCommand}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    Verb = "runas"
                };

                using (Process proc = new Process { StartInfo = psi })
                {
                    proc.Start();
                    sb.AppendLine(proc.StandardOutput.ReadToEnd());
                    sb.AppendLine(proc.StandardError.ReadToEnd());
                    proc.WaitForExit();
                }

                sb.AppendLine("✅ Adapter toggled and set to DHCP/automatic DNS.");

                // Reset TCP/IP, Winsock, flush DNS via separate elevated cmd.exe
                void RunNetsh(string arguments)
                {
                    var netshProc = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/c {arguments}",
                            UseShellExecute = true,
                            Verb = "runas",
                            CreateNoWindow = true
                        }
                    };
                    netshProc.Start();
                    netshProc.WaitForExit();
                }

                RunNetsh("netsh int ip reset");
                RunNetsh("netsh winsock reset");
                RunNetsh("ipconfig /flushdns");

                sb.AppendLine("✅ Network reset finished.");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"❌ Exception: {ex.Message}");
            }

            return sb.ToString();
        }

        private async void wipemods_Click(object sender, EventArgs e)
        {
            progPanel.Visible = true;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                Report(0, "Scanning for mods...");

                // Call your static RemoveAllMods method
                string result = RemoveAllMods();

                Report(100, "Done!");

                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = result;
                    progPanel.Visible = false;
                }));
            });
        }

        public static string RemoveAllMods()
        {
            StringBuilder sb = new StringBuilder();

            if (string.IsNullOrWhiteSpace(GamePath) || !Directory.Exists(GamePath))
            {
                sb.AppendLine("Helldivers 2 not found. Skipping mod removal.");
                return sb.ToString();
            }

            string dataFolder = Path.Combine(GamePath, "data");
            if (!Directory.Exists(dataFolder))
            {
                sb.AppendLine("Data folder not found. Skipping mod removal.");
                return sb.ToString();
            }

            bool filesFound = false;

            foreach (var file in Directory.GetFiles(dataFolder))
            {
                string fileName = Path.GetFileName(file);
                string filePath = Path.Combine(dataFolder, fileName);

                // Match 16-character hex IDs ending with .patch_
                var match = System.Text.RegularExpressions.Regex.Match(fileName, @"([0-9a-fA-F]{16})\.patch_");
                if (match.Success)
                {
                    filesFound = true;
                    string hex = match.Groups[1].Value;

                    if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                        sb.AppendLine($"Deleted: {fileName}");
                    }

                    // Delete sibling files with same hex in their name
                    foreach (var siblingFile in Directory.GetFiles(dataFolder)
                                                       .Where(f => Path.GetFileName(f).Contains(hex)))
                    {
                        if (File.Exists(siblingFile))
                        {
                            File.Delete(siblingFile);
                            sb.AppendLine($"Deleted: {Path.GetFileName(siblingFile)}");
                        }
                    }
                }
            }

            if (!filesFound)
            {
                sb.AppendLine("No mod files were found to remove.");
            }
            else
            {
                sb.AppendLine("Removed all .patch_ files and sibling files sharing the same IDs. Please verify game integrity before launching.");
            }

            return sb.ToString();
        }

        private async void wipeshaders_Click(object sender, EventArgs e)
        {
            progPanel.Visible = true;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                string shaderCachePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Arrowhead\Helldivers2\shader_cache"
                );

                if (!Directory.Exists(shaderCachePath))
                {
                    this.Invoke(new Action(() =>
                    {
                        richTextBox1.Text = $"Shader cache folder not found: {shaderCachePath}";
                        progPanel.Visible = false;
                    }));
                    return;
                }

                var files = Directory.GetFiles(shaderCachePath, "*", SearchOption.AllDirectories);
                int total = files.Length;
                int count = 0;

                Report(0, "Deleting shader cache...");

                foreach (var file in files)
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch (Exception ex)
                    {
                        // Log error if needed
                    }

                    count++;
                    int percent = (int)((count / (double)total) * 100);
                    Report(percent, $"Deleting shader cache... ({count}/{total})");
                }

                // Optionally remove empty directories
                foreach (var dir in Directory.GetDirectories(shaderCachePath, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        Directory.Delete(dir, true);
                    }
                    catch { }
                }

                Report(100, "Done!");

                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = $"Shader cache cleared: {shaderCachePath}";
                    progPanel.Visible = false;
                }));
            });
        }

        private async void wipeappdata_Click(object sender, EventArgs e)
        {
            progPanel.Visible = true;
            progressBar1.Value = 0;
            progressLabel.Text = "";

            await Task.Run(() =>
            {
                void Report(int percent, string msg = "")
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar1.Value = percent;
                        progressLabel.Text = $"{percent}% {msg}";
                    }));
                }

                string arrowheadPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Arrowhead"
                );

                if (!Directory.Exists(arrowheadPath))
                {
                    this.Invoke(new Action(() =>
                    {
                        richTextBox1.Text = $"Arrowhead folder not found: {arrowheadPath}";
                        progPanel.Visible = false;
                    }));
                    return;
                }

                // Get all files recursively
                var files = Directory.GetFiles(arrowheadPath, "*", SearchOption.AllDirectories);
                int totalFiles = files.Length;
                int count = 0;

                Report(0, "Deleting files in Arrowhead folder...");

                foreach (var file in files)
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch { /* optionally log errors */ }

                    count++;
                    int percent = (int)((count / (double)totalFiles) * 100);
                    Report(percent, $"Deleting files... ({count}/{totalFiles})");
                }

                // Delete all subdirectories
                var directories = Directory.GetDirectories(arrowheadPath, "*", SearchOption.AllDirectories);
                foreach (var dir in directories)
                {
                    try
                    {
                        Directory.Delete(dir, true);
                    }
                    catch { }
                }

                Report(100, "Done!");

                this.Invoke(new Action(() =>
                {
                    richTextBox1.Text = $"Arrowhead folder cleared: {arrowheadPath}";
                    progPanel.Visible = false;
                }));
            });
        }
    }

    /*--------------progress class section - begin--------------*/

    public class ProgressForm : Form
    {
        public ProgressBar progressBar;
        public Label lblStatus;

        public ProgressForm()
        {
            this.ControlBox = false;
            this.StartPosition = FormStartPosition.CenterParent;
            this.Size = new System.Drawing.Size(300, 100);

            progressBar = new ProgressBar()
            {
                Minimum = 0,
                Maximum = 100,
                Value = 0,
                Dock = DockStyle.Top
            };
            lblStatus = new Label()
            {
                Text = "",
                Dock = DockStyle.Bottom,
                TextAlign = System.Drawing.ContentAlignment.MiddleCenter
            };

            this.Controls.Add(progressBar);
            this.Controls.Add(lblStatus);
        }

        public void UpdateProgress(int percent, string message = "")
        {
            if (InvokeRequired)
                this.Invoke(new Action(() => { progressBar.Value = percent; lblStatus.Text = message; }));
            else
                progressBar.Value = percent;
            lblStatus.Text = message;
        }
    }

    /*--------------progress class section - end--------------*/

}
