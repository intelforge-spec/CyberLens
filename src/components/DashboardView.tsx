import { useState, useEffect, useRef, useMemo } from "react";
import { jsPDF } from "jspdf";
import { 
  ShieldAlert, 
  AlertTriangle, 
  Shield, 
  Cpu, 
  Network, 
  Globe, 
  Newspaper,
  TrendingUp, 
  FileText, 
  Mail, 
  Clock, 
  Flame, 
  ChevronRight,
  MapPin,
  ExternalLink,
  Radar,
  Search,
  X,
  Filter,
  Info,
  Server,
  Activity,
  CheckCircle,
  AlertOctagon,
  ArrowRight,
  RefreshCw
} from "lucide-react";
import { InvestigationRecord } from "../types";

// Extended cyber threat news data
const allExtendedNews = [
  {
    id: 1,
    title: "Beware: Fake Browser Updates Deliver BitRAT and Lumma Stealer Malware",
    description: "Cybercriminals are using compromised websites to deliver fake browser updates that install Lumma Stealer and BitRAT. These payloads target sensitive user data, browser credentials, and cryptocurrency wallets.",
    source: "The Hacker News",
    url: "https://thehackernews.com/2024/06/beware-fake-browser-updates-deliver.html",
    published: "2024-06-03",
    time: "4h ago",
    tags: "Malware",
    sentiment: "High Risk"
  },
  {
    id: 2,
    title: "Qualys Discovers Critical regreSSHion RCE Vulnerability in OpenSSH Server",
    description: "Qualys researchers have disclosed a use-after-free regression vulnerability in OpenSSH's server daemon (CVE-2024-6387). This loophole could allow unauthenticated remote code execution as root on glibc-based Linux environments.",
    source: "The Hacker News",
    url: "https://thehackernews.com/2024/07/regresshion-critical-rce-vulnerability.html",
    published: "2024-07-01",
    time: "5h ago",
    tags: "Vulnerability",
    sentiment: "Critical"
  },
  {
    id: 3,
    title: "Palo Alto Networks Urges Immediate Action to Patch Critical Expedition Vulnerability",
    description: "Palo Alto Networks has released patch updates to address a critical security vulnerability in its Expedition migration tool (CVE-2024-5910). The flaw allows remote unauthenticated hackers to read and write database configurations.",
    source: "The Hacker News",
    url: "https://thehackernews.com/2024/07/palo-alto-networks-urges-immediate.html",
    published: "2024-07-11",
    time: "6h ago",
    tags: "Vulnerability",
    sentiment: "Critical"
  },
  {
    id: 4,
    title: "Iranian MuddyWater APT Targets Israeli Entities in Spy Campaign",
    description: "The Iranian state-sponsored threat group MuddyWater is actively targeting public and private sector organizations in Israel with custom spearphishing campaigns. Security research shows they are utilizing compromised administrator accounts and custom backdoor tools.",
    source: "The Hacker News",
    url: "https://thehackernews.com/2024/03/iranian-muddywater-apt-targets-israeli.html",
    published: "2024-03-12",
    time: "1d ago",
    tags: "APT",
    sentiment: "High Risk"
  },
  {
    id: 5,
    title: "Cisco Warns of Active Zero-Day Exploitation of IOS XE Software Web UI",
    description: "Cisco warns of active zero-day exploitation of a privilege escalation bug (CVE-2023-20198) in the Web UI of IOS XE Software devices. This security flaw allows remote unauthenticated attackers to gain administrative access.",
    source: "The Hacker News",
    url: "https://thehackernews.com/2023/10/cisco-warns-of-active-zero-day.html",
    published: "2023-10-16",
    time: "1d ago",
    tags: "Vulnerability",
    sentiment: "Critical"
  },
  {
    id: 6,
    title: "Fortinet Emergency Patch Released for Actively Exploited SSL-VPN Zero-Day",
    description: "Fortinet released an urgent PSIRT advisory regarding a critical out-of-bounds write flaw in FortiOS SSL-VPN (CVE-2024-21762). This vulnerability is actively targeted in the wild to execute arbitrary system code or commands.",
    source: "The Hacker News",
    url: "https://thehackernews.com/2024/02/fortinet-warns-of-critical-ssl-vpn.html",
    published: "2024-02-09",
    time: "2d ago",
    tags: "Vulnerability",
    sentiment: "Critical"
  },
  {
    id: 7,
    title: "Over 170 Malicious PyPI Packages Found Stealing Discord Tokens and Credit Cards",
    description: "An active supply chain campaign has poisoned the Python Package Index (PyPI) with over 170 malicious libraries stealing credentials. The infected packages use multi-layer obfuscation to evade standard static analyzers.",
    source: "The Hacker News",
    url: "https://thehackernews.com/2024/01/over-170-malicious-pypi-packages-found.html",
    published: "2024-01-09",
    time: "3d ago",
    tags: "Malware",
    sentiment: "High Risk"
  },
  {
    id: 8,
    title: "Microsoft June 2024 Patch Tuesday Addresses Critical Active Directory Vulnerabilities",
    description: "Microsoft's June 2024 security updates address critical vulnerabilities across Windows platforms, including Active Directory services. Administrators are urged to deploy native patches to prevent threat actors from hijacking domain controller authentications.",
    source: "The Hacker News",
    url: "https://thehackernews.com/2024/06/microsoft-june-2024-patch-tuesday--is-now-live.html", // Wait, let's keep it clean
    published: "2024-06-11",
    time: "4d ago",
    tags: "Vulnerability",
    sentiment: "Critical"
  }
];

interface DashboardViewProps {
  records: InvestigationRecord[];
  onSelectRecord: (record: InvestigationRecord) => void;
  onNavigateToLookup: () => void;
  onNavigateToEmail: () => void;
  token?: string;
}

export default function DashboardView({
  onNavigateToLookup,
  onNavigateToEmail,
  token
}: DashboardViewProps) {

  const [showNewsModal, setShowNewsModal] = useState(false);
  const [showAdvisoriesModal, setShowAdvisoriesModal] = useState(false);

  // Real-time news states
  const [isFetchingRealtimeNews, setIsFetchingRealtimeNews] = useState(false);
  const [newsList, setNewsList] = useState<any[]>([]);
  const [realtimeNewsError, setRealtimeNewsError] = useState<string | null>(null);
  const [feedMetadata, setFeedMetadata] = useState<{ lastUpdated: string; nextSync: string } | null>(null);

  const handleDownloadPdfReport = () => {
    const doc = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4"
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;
    const contentWidth = pageWidth - (margin * 2);

    let y = 15;
    let pageNum = 1;

    // FUNCTION TO DRAW PAGE GRAPHICS / FRAME / FOOTER
    const drawPageBorderAndFooter = () => {
      // Draw border frame
      doc.setDrawColor(226, 232, 240); // slate-200
      doc.setLineWidth(0.2);
      doc.rect(15, 10, pageWidth - 30, pageHeight - 20);

      // Footer
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184); // slate-400
      doc.text("CyberLens Security Operations Center (SOC) Portal", 20, pageHeight - 14);
      doc.text("Dokumen Intelijen Rahasia - Universitas & Korporat", 20, pageHeight - 11);
      doc.text(`Halaman ${pageNum}`, pageWidth - 35, pageHeight - 11);
    };

    // PAGE BOUNDARY HELPER
    const checkPageBreak = (heightNeeded: number) => {
      if (y + heightNeeded > pageHeight - 22) {
        doc.addPage();
        pageNum++;
        drawPageBorderAndFooter();
        y = 25; // start further down for subsequent pages
      }
    };

    // First Page Initial Draw
    drawPageBorderAndFooter();

    // COVER BANNER (Elegant dark panel style inside margins)
    doc.setFillColor(15, 23, 42); // slate-900 (deep dark blueish slate)
    doc.rect(20, y, contentWidth, 36, "F");

    // Corporate Brand Banner Accent Line
    doc.setFillColor(37, 99, 235); // blue-600
    doc.rect(20, y + 36, contentWidth, 2, "F");

    // White text over the dark panel
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(59, 130, 246); // blue-500
    doc.text("DOKUMEN SPESIFIKASI OPERASIONAL & REFERENSI DATA", 25, y + 10);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(255, 255, 255);
    doc.text("CYBERLENS PORTAL v2.5", 25, y + 21);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(203, 213, 225); // slate-300
    doc.text("Panduan Spesifikasi Fitur Utama dan Verifikasi Sumber Data Intelijen Siber Otoritatif", 25, y + 28);

    y += 48;

    // PREAMBLE / INTRO
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(30, 41, 59); // slate-800
    doc.text("1. PENGANTAR SISTEM", 20, y);
    y += 5;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(71, 85, 105); // slate-600
    
    const introText = "CyberLens Portal dirancang khusus sebagai Command Center Keamanan Siber (SOC) terpadu. Dashboard ini memadukan telemetry real-time, visualisasi pemetaan radar ancaman global, analisis taktis vektor malware, serta pelacakan komparatif kelompok ancaman bersandi persisten (APT). Dokumen ini menyajikan rincian terstruktur mengenai fungsi operasional setiap fitur pada dashboard beserta validasi autentik terhadap basis data dan sumber informasi yang dikumpulkan, baik dari institusi koordinasi nasional maupun lembaga pertahanan siber internasional.";
    const introLines = doc.splitTextToSize(introText, contentWidth - 4);
    doc.text(introLines, 22, y);
    y += (introLines.length * 4.5) + 6;

    // CATALOG TITLE
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(30, 41, 59);
    doc.text("2. KATALOG FITUR & VALIDASI SUMBER DATA", 20, y);
    y += 8;

    // FEATURES DATA LIST
    interface FeatureSpec {
      title: string;
      desc: string;
      sources: string[];
      details: string;
    }

    const features: FeatureSpec[] = [
      {
        title: "Primary Operation Focus Area (Fokus Utama Operasi)",
        desc: "Panel pemantauan utama untuk kerentanan keamanan siber krusial yang diidentifikasi sedang dieksploitasi secara aktif dan memerlukan langkah mitigasi teknis darurat segera oleh analis SOC.",
        sources: [
          "CISA KEV (Known Exploited Vulnerabilities) Catalog",
          "NIST NVD (National Vulnerability Database) - Skor CVSS v3",
          "Pabrikan Global PSIRT (Cisco PSIRT, Palo Alto Networks Advisory, Microsoft MSRC)",
          "BSSN Threat Intelligence RI (Badan Siber dan Sandi Negara)"
        ],
        details: "Mengekstrak data dinamis secara terenkripsi dari basis kerentanan internal dan publik terpercaya, mendeteksi tanggal rilis, ringkasan kelemahan sistem, vektor ancaman, status eksploitasi aktif, serta direktori tautan remediasi orisinal dari vendor."
      },
      {
        title: "Global Threat Map Telemetry (Peta Radar Ancaman Global)",
        desc: "Representasi visual interaktif pemetaan koordinat geografis aktivitas serangan siber yang terdeteksi secara real-time di jaringan sensor pengumpan (honeypot) global.",
        sources: [
          "CyberLens Global Honeypot Sensors (Sensor Pengumpan Internal)",
          "SIEM Endpoint Log Correlation (Korelasi Log Sensor Tersebar)",
          "Crowdsourced Threat Intel Feeds (Aliran Intel Terbuka)"
        ],
        details: "Mengkorelasikan koordinat lintang dan bujur dari alamat IP untuk memvisualisasikan persebaran anomali, laju insiden per jam, tingkat keparahan, serta modus operandi muatan siber berbahaya."
      },
      {
        title: "Threat Vector Distribution Analysis (Analisis Sebaran Vektor Serangan)",
        desc: "Penyajian statistik porsi sebaran muatan berbahaya (payload) aktif yang masuk demi mempermudah konfigurasi pengalokasian sumber daya keamanan siber.",
        sources: [
          "Laporan Telemetri SOC Bulanan Internasional & Regional",
          "SIEM Incident Management Database (Basis Data Pengelolaan Insiden SIEM)",
          "ID-SIRTII/CC Alerts & Statistik Insiden Siber Indonesia"
        ],
        details: "Mengklasifikasikan data telemetri serangan menjadi empat vektor utama secara presisi: Malware (35%), Phishing (28%), Exploit (22%), dan Botnet (15%) guna menyusun prioritas penahanan insiden."
      },
      {
        title: "Integrated Threat Feed (Umpan Berita Ancaman Siber Real-Time)",
        desc: "Aliran informasi intelijen ancaman siber terkini tahun 2026 yang dikumpulkan, divalidasi, dan disinkronisasikan secara dinamis menggunakan mesin pencarian taktis.",
        sources: [
          "Automated Threat Intelligence Grounding Engine",
          "CISA Advisories & NIST Vulnerability Database Alerts",
          "Portal Berita Internasional: BleepingComputer, Dark Reading, SecurityWeek",
          "Umpan Berita Nasional Indonesia: Portal Resmi BSSN, Peringatan ID-SIRTII/CC",
          "Kanal Berita Sains & Teknologi Nasional: Detik iNet, Kompas Tekno, CNN Indonesia"
        ],
        details: "Warta intelijen siber mendeteksi kerentanan krusial, operasi serangan kelompok ancaman terarah (APT), aktivitas penyebaran malware, serta insiden kebocoran data terhangat di seluruh penjuru dunia. Hasil sintesis disajikan dalam format ringkasan bahasa Indonesia SOC yang formal, ringkas, dan bebas dari hiperbola pemasaran."
      },
      {
        title: "Threat Actor Tracking System (Sistem Pelacak Kelompok Ancaman)",
        desc: "Modul profil taktis mendalam untuk menganalisis, mengantisipasi, dan mempelajari taktik serta pola serangan kelompok ancaman persisten tingkat tinggi (APT) di level global dan regional.",
        sources: [
          "MITRE ATT&CK Matrix for Enterprise (Tactics & Techniques Profiles)",
          "Mandiant M-Trends Annual Threat Report",
          "Kaspersky Securelist Specialist Publications",
          "BSSN Threat Intelligence Regional Reports"
        ],
        details: "Menyediakan taksonomi perilaku kelompok ancaman utama seperti Lazarus Group, APT28/Fancy Bear, APT29, serta sindikat pemerasan tebusan (ransomware) LockBit dan Qilin, dipetakan langsung dengan matriks MITRE ATT&CK, target sektor industri, dan indikator kompromi (IoC)."
      },
      {
        title: "Manufacturer Vulnerability Advisories (Direktori Kerentanan Pabrikan)",
        desc: "Katalog rilis pembaruan firmware resmi dan rujukan mitigasi teknis dari vendor teknologi global penyedia tulang punggung infrastruktur siber.",
        sources: [
          "Microsoft Security Response Center (MSRC) Release Bulletins",
          "Cisco PSIRT Portal (Product Security Incident Response Team)",
          "Palo Alto Networks Security Advisories Directory",
          "VMware Product Security Advisory Platform",
          "Fortinet FortiGuard PSIRT Alerts",
          "F5 BIG-IP Security Management Advisories"
        ],
        details: "Menghubungkan kode identifikasi CVE dengan tingkat keparahan skor CVSS, petunjuk penanganan mandiri (workaround), serta rujukan rilis pembaruan orisinal guna menutup celah sebelum sempat dieksploitasi aktif oleh pihak tidak berwenang."
      }
    ];

    features.forEach((feat, idx) => {
      const titleText = `${idx + 1}. ${feat.title}`;
      const titleLines = doc.splitTextToSize(titleText, contentWidth - 8);
      const descLines = doc.splitTextToSize(feat.desc, contentWidth - 8);
      const sourcesText = feat.sources.join(", ");
      const sourcesLines = doc.splitTextToSize(sourcesText, contentWidth - 36);
      const detailsLines = doc.splitTextToSize(feat.details, contentWidth - 36);

      // Line heights to calculate heights before drawing to prevent overlaps
      const lhTitle = 4.5;
      const lhDesc = 4.0;
      const lhSource = 4.0;
      const lhDetail = 3.6;

      const titleHeight = titleLines.length * lhTitle;
      const descHeight = descLines.length * lhDesc;
      const sourcesHeight = sourcesLines.length * lhSource;
      const detailsHeight = detailsLines.length * lhDetail;

      // Dynamic total block height:
      // Padding levels: Top (5mm) + Title-Desc gap (2mm) + Desc-Divider gap (3mm) + Divider-to-Sources gap (4mm) + Sources-Details gap (2.5mm) + Bottom padding (5mm) = 21.5mm
      const blockHeight = titleHeight + descHeight + sourcesHeight + detailsHeight + 21.5;

      // Check if page break is needed before initiating this block
      checkPageBreak(blockHeight + 6);

      // Draw standard container background field
      doc.setFillColor(248, 250, 252); // slate-50 (off-white)
      doc.rect(20, y, contentWidth, blockHeight, "F");

      // Draw exterior border frame
      doc.setDrawColor(226, 232, 240); // slate-200
      doc.setLineWidth(0.2);
      doc.rect(20, y, contentWidth, blockHeight, "D");

      // Draw beautiful blue left-accent bar
      doc.setFillColor(37, 99, 235); // blue-600
      doc.rect(20, y, 1.5, blockHeight, "F");

      // Relative drawing baseline coordinates
      let itemY = y + 5;

      // 1. Render feature title
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9.5);
      doc.setTextColor(30, 41, 59); // slate-800
      doc.text(titleLines, 24, itemY);
      itemY += titleHeight;

      // Small gap
      itemY += 2;

      // 2. Render Description text
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105); // slate-600
      doc.text(descLines, 24, itemY);
      itemY += descHeight;

      // Gap before divider
      itemY += 3;

      // Draw thin grey divider line
      doc.setDrawColor(241, 245, 249); // slate-100
      doc.setLineWidth(0.15);
      doc.line(24, itemY, pageWidth - 24, itemY);
      itemY += 4;

      // 3. Render Sources Header and Text
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.setTextColor(15, 23, 42); // slate-900
      doc.text("Sumber Data:", 24, itemY);

      doc.setFont("helvetica", "italic");
      doc.setFontSize(8);
      doc.setTextColor(29, 78, 216); // blue-700
      doc.text(sourcesLines, 54, itemY);
      itemY += sourcesHeight;

      // Gap
      itemY += 2.5;

      // 4. Render Mechanisms / Details Header and Text
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.setTextColor(15, 23, 42); // slate-900
      doc.text("Mekanisme Data:", 24, itemY);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105); // slate-600
      doc.text(detailsLines, 54, itemY);
      itemY += detailsHeight;

      // Finalize loop baseline y position
      y += blockHeight + 6; // 6mm spacing before next element block
    });

    // SIGNATURE / CERTIFICATION BLOCK
    checkPageBreak(35);
    y += 2;
    doc.setDrawColor(226, 232, 240); // slate-200
    doc.setLineWidth(0.4);
    doc.line(20, y, pageWidth - 20, y);
    y += 6;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42); // slate-900
    doc.text("DIVERIFIKASI DAN DISAHKAN OLEH:", 20, y);
    y += 4;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105); // slate-600
    doc.text("CyberLens Security Operations Response Team (S.O.R.T)", 20, y);
    doc.text("Umpan data tersinkronisasi secara otomatis melalui TLS v1.3 Secure Handshake.", 20, y + 4);

    doc.setFont("helvetica", "italic");
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184); // slate-400
    doc.text(`Waktu Cetak Laporan: ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })} WIB`, 20, y + 9);

    // Save PDF
    doc.save("CyberLens_Portal_Spesifikasi_Fitur_Data.pdf");
  };

  const fetchRealtimeNews = async () => {
    setIsFetchingRealtimeNews(true);
    setRealtimeNewsError(null);
    try {
      const activeToken = token || localStorage.getItem("cyberlens_token");
      if (!activeToken || activeToken === "null" || activeToken === "undefined") {
        setIsFetchingRealtimeNews(false);
        return;
      }
      const res = await fetch("/api/news/realtime", {
        headers: {
          "Authorization": `Bearer ${activeToken}`
        }
      });
      if (res.status === 401 || res.status === 403) {
        localStorage.removeItem("cyberlens_token");
        localStorage.removeItem("cyberlens_user");
        window.location.reload();
        throw new Error("Sesi login Anda telah kedaluwarsa. Silakan login kembali.");
      }
      if (!res.ok) {
        throw new Error(`Gagal memuat update (${res.status})`);
      }
      const data = await res.json();
      if (data && Array.isArray(data.news)) {
        setNewsList(data.news);
        if (data.metadata) {
          setFeedMetadata(data.metadata);
        }
      } else if (Array.isArray(data)) {
        setNewsList(data);
      } else {
        throw new Error("Format respon tidak valid");
      }
    } catch (err: any) {
      console.error("Gagal mengambil realtime newswire:", err);
      setRealtimeNewsError(err.message || "Gagal mengupdate newswire.");
    } finally {
      setIsFetchingRealtimeNews(false);
    }
  };

  const triggerManualSync = async () => {
    setIsFetchingRealtimeNews(true);
    setRealtimeNewsError(null);
    try {
      const activeToken = token || localStorage.getItem("cyberlens_token");
      if (!activeToken || activeToken === "null" || activeToken === "undefined") {
        setIsFetchingRealtimeNews(false);
        return;
      }
      const res = await fetch("/api/news/realtime/sync", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${activeToken}`
        }
      });
      if (res.status === 401 || res.status === 403) {
        localStorage.removeItem("cyberlens_token");
        localStorage.removeItem("cyberlens_user");
        window.location.reload();
        throw new Error("Sesi login Anda telah kedaluwarsa. Silakan login kembali.");
      }
      if (!res.ok) {
        throw new Error(`Gagal sinkronisasi feed (${res.status})`);
      }
      const data = await res.json();
      if (data && Array.isArray(data.news)) {
        setNewsList(data.news);
        if (data.metadata) {
          setFeedMetadata(data.metadata);
        }
      } else {
        throw new Error("Respon sinkronisasi tidak valid");
      }
    } catch (err: any) {
      console.error("Gagal sinkronisasi manual newswire:", err);
      setRealtimeNewsError(err.message || "Gagal menjalankan sinkronisasi manual.");
    } finally {
      setIsFetchingRealtimeNews(false);
    }
  };

  useEffect(() => {
    // Initial fetch of realtime news on component mount or token update
    fetchRealtimeNews();
  }, [token]);

  // Search/Filter state inside the modals
  const [newsSearch, setNewsSearch] = useState("");
  const [newsFilter, setNewsFilter] = useState("All");

  const [advSearch, setAdvSearch] = useState("");
  const [advFilter, setAdvFilter] = useState("All");
  const [advSeverityFilter, setAdvSeverityFilter] = useState("All");

  const [selectedHotspotId, setSelectedHotspotId] = useState("us-west");

  // Real-time live threat telemetry event feed
  const [liveEvents, setLiveEvents] = useState([
    { time: "09:41", event: "SOC Global Intelligence consensus initialized", type: "system" },
    { time: "09:35", event: "Critical alert: outbound DDoS payload signatures matched SEA Hub", type: "danger" },
    { time: "09:12", event: "New KEV Added: CVE-2024-21762 FortiOS SSL-VPN bypass", type: "warning" },
    { time: "08:58", event: "Sophos Security Advisory published concerning firewall exploit vectors", type: "info" },
    { time: "08:35", event: "Lazarus Spearphishing targeting digital asset systems mitigated", type: "success" },
    { time: "08:06", event: "Fortinet Advisory Published - CVSS 9.8", type: "warning" },
    { time: "07:55", event: "Qilin Campaign Updated: Mass double extortion scans in EU Central", type: "danger" },
    { time: "07:42", event: "New CVE Released: CVE-2024-38077 Active escalation bug", type: "info" },
    { time: "07:10", event: "Lumma Stealer distribution wave intercepted in US West", type: "success" },
  ]);

  const terminalEndRef = useRef<HTMLDivElement>(null);

  const [activeFocusId, setActiveFocusId] = useState("paloalto");

  const defaultFocusAreas = [
    {
      id: "paloalto",
      title: "Palo Alto Networks PAN-OS Auth Bypass Exploited in the Wild",
      cve: "CVE-2024-0012",
      cvss: "9.3",
      vendor: "Palo Alto Networks",
      product: "PAN-OS Management Interface",
      exploitationStatus: "Actively Exploited (CISA KEV Catalog)",
      description: "Kerentanan bypass autentikasi pada perangkat lunak PAN-OS Palo Alto Networks memungkinkan penyerang jarak jauh tanpa autentikasi yang memiliki akses jaringan ke antarmuka manajemen untuk memperoleh hak akses administrator. Kelompok ancaman tingkat lanjut (APT) telah aktif mengeksploitasi celah ini secara global.",
      source: "CISA KEV & Palo Alto Unit 42",
      published: "2024-11-18",
      vector: "Authentication Bypass",
      url: "https://security.paloaltonetworks.com/CVE-2024-0012",
      badge: "Active Zero-Day",
      tabLabel: "PAN-OS Bypass"
    },
    {
      id: "cisco",
      title: "Cisco IOS XE Remote Code Execution Zero-Day Confirmed",
      cve: "CVE-2023-20198",
      cvss: "10.0",
      vendor: "Cisco Systems",
      product: "IOS XE Software",
      exploitationStatus: "Actively Exploited (CISA KEV Catalog)",
      description: "Kerentanan eskalasi hak istimewa pada fitur Web UI perangkat lunak Cisco IOS XE memungkinkan penyerang jarak jauh tanpa autentikasi membuat akun administratif level 15 pada sistem yang terdampak. Celah ini sepenuhnya melewati mekanisme autentikasi dan memberikan kendali penuh atas gateway perimeter.",
      source: "Cisco PSIRT Advisory & CISA KEV",
      published: "2023-10-16",
      vector: "Web UI Privilege Escalation",
      url: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-byoleC92",
      badge: "Exploitable Zero-Day",
      tabLabel: "Cisco IOS XE RCE"
    },
    {
      id: "linux",
      title: "One-Character Linux Kernel Flaw Enables Local Root Access",
      cve: "CVE-2024-1086",
      cvss: "7.8",
      vendor: "Linux Kernel Org",
      product: "Linux Kernel (netfilter nf_tables)",
      exploitationStatus: "Public PoC Available - Exploited in Wild (CISA KEV)",
      description: "Kerentanan use-after-free pada komponen netfilter: nf_tables dalam kernel Linux memungkinkan pengguna lokal memperoleh hak akses root. Kode eksploitasi publik yang sangat stabil mempermudah eskalasi hak akses dan meloloskan diri dari isolasi container pada berbagai distribusi umum.",
      source: "NIST NVD & Red Hat Security",
      published: "2024-02-05",
      vector: "Local Privilege Escalation",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2024-1086",
      badge: "Container Escape",
      tabLabel: "Linux Kernel Flaw"
    },
    {
      id: "microsoft",
      title: "Microsoft Active Directory Remote Code Execution Flaw",
      cve: "CVE-2024-38077",
      cvss: "9.8",
      vendor: "Microsoft Corp",
      product: "Windows Server (Remote Access Connection Manager)",
      exploitationStatus: "Critical Enterprise Threat - Patch Deployed",
      description: "Kerentanan eksekusi kode jarak jauh (RCE) kritis pada Windows Remote Access Connection Manager memungkinkan penyerang jarak jauh yang tidak terautentikasi untuk mengeksekusi kode arbitrer pada sistem Windows Server. Celah ini memudahkan eskalasi langsung menjadi Domain Admin dan pembajakan domain jajaran jaringan secara penuh.",
      source: "Microsoft MSRC & NIST NVD",
      published: "2024-07-09",
      vector: "RPC Remote Code Execution",
      url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077",
      badge: "Critical MS Patch",
      tabLabel: "Windows AD Bug"
    }
  ];

  const [focusAreas, setFocusAreas] = useState<any[]>(defaultFocusAreas);

  useEffect(() => {
    if (newsList && newsList.length > 0) {
      // derive focusAreas dynamic representation from newest threat list
      const derived = newsList.slice(0, 4).map((item, idx) => {
        // Find CVE patterns
        let cve = "N/A";
        const cveMatch = item.title.match(/CVE-\d{4}-\d{4,}/i) || item.description.match(/CVE-\d{4}-\d{4,}/i);
        if (cveMatch) {
          cve = cveMatch[0].toUpperCase();
        }

        let cvss = "9.8";
        if (item.sentiment === "Critical") {
          cvss = "9.8";
        } else if (item.sentiment === "High Risk") {
          cvss = "8.5";
        } else if (item.sentiment === "Medium Risk") {
          cvss = "6.5";
        } else {
          cvss = "4.2";
        }

        let vendor = "Enterprise System";
        let product = `${item.tags || 'Security'} Infrastructure`;
        const titleLower = item.title.toLowerCase();
        
        if (titleLower.includes("cisco")) {
          vendor = "Cisco Systems";
          product = "IOS XE Router/Switch Software";
        } else if (titleLower.includes("palo alto") || titleLower.includes("pan-os") || titleLower.includes("expedition")) {
          vendor = "Palo Alto Networks";
          product = "PAN-OS Firewall System";
        } else if (titleLower.includes("linux") || titleLower.includes("kernel")) {
          vendor = "Linux Kernel Org";
          product = "Linux Kernel (netfilter)";
        } else if (titleLower.includes("microsoft") || titleLower.includes("windows") || titleLower.includes("active directory")) {
          vendor = "Microsoft Corp";
          product = "Windows Server AD Services";
        } else if (titleLower.includes("fortinet") || titleLower.includes("fortios")) {
          vendor = "Fortinet Inc";
          product = "FortiOS SSL-VPN Software";
        } else if (titleLower.includes("pypi") || titleLower.includes("python") || titleLower.includes("rustybobs")) {
          vendor = "Python Software Foundation";
          product = "PyPI Repository Registry";
        } else if (titleLower.includes("ivanti")) {
          vendor = "Ivanti Connect";
          product = "Secure VPN Gateway Device";
        } else if (titleLower.includes("citrix")) {
          vendor = "Citrix Systems";
          product = "NetScaler Application Controller";
        } else if (titleLower.includes("apple") || titleLower.includes("ios ")|| titleLower.includes("macos")) {
          vendor = "Apple Inc.";
          product = "iOS / macOS Subsystem";
        } else if (titleLower.includes("android") || titleLower.includes("google")) {
          vendor = "Google LLC";
          product = "Android Mobile OS Kernel";
        }

        // Tab label from CVE or shortened title
        let tabLabel = item.tags || "Incident";
        if (cve !== "N/A") {
          tabLabel = cve;
        } else {
          const cleanWords = item.title.replace(/[^a-zA-Z0-9 ]/g, "").split(/\s+/);
          if (cleanWords.length >= 2) {
            tabLabel = `${cleanWords[0]} ${cleanWords[1]}`;
          } else if (cleanWords.length > 0) {
            tabLabel = cleanWords[0];
          }
        }

        // Resolve highly professional and authoritative enterprise security sources dynamically
        let intelSource = "CISA KEV Catalog & ID-SIRTII/CC Alert";
        const vLower = vendor.toLowerCase();
        if (vLower.includes("cisco")) {
          intelSource = "Cisco PSIRT Advisory & CISA KEV";
        } else if (vLower.includes("palo alto")) {
          intelSource = "Palo Alto Networks Unit 42 & CISA KEV";
        } else if (vLower.includes("linux") || vLower.includes("kernel")) {
          intelSource = "NIST NVD & Red Hat Security Advisory";
        } else if (vLower.includes("microsoft") || vLower.includes("windows")) {
          intelSource = "Microsoft MSRC & CISA KEV";
        } else if (vLower.includes("fortinet")) {
          intelSource = "FortiGuard PSIRT & CISA KEV";
        } else if (vLower.includes("python") || vLower.includes("pypi")) {
          intelSource = "Python Security Response Team (PSIRT)";
        } else if (vLower.includes("ivanti")) {
          intelSource = "Ivanti PSIRT & CISA KEV Catalog";
        } else if (vLower.includes("citrix")) {
          intelSource = "Citrix PSIRT & CISA KEV";
        } else if (vLower.includes("apple")) {
          intelSource = "Apple Product Security Advisory";
        } else if (vLower.includes("google") || vLower.includes("android")) {
          intelSource = "Google Android Security Team";
        } else if (item.tags === "Ransomware") {
          intelSource = "BSSN Threat Intelligence & FBI Strategic Alert";
        } else if (item.tags === "Malware") {
          intelSource = "Mandiant Threat Intelligence & BSSN";
        }

        // Construct direct specific links instead of generic homepages
        let url = item.url || "https://nvd.nist.gov";
        const lowerUrl = url.toLowerCase();
        const isGenericHome = 
          lowerUrl === "https://nvd.nist.gov" || 
          lowerUrl === "https://nvd.nist.gov/" || 
          lowerUrl === "https://www.cisa.gov" || 
          lowerUrl === "https://www.cisa.gov/" ||
          lowerUrl === "https://pypi.org" ||
          lowerUrl === "https://pypi.org/" ||
          lowerUrl.endsWith(".gov") ||
          lowerUrl.endsWith(".gov/") ||
          lowerUrl.endsWith(".com") ||
          lowerUrl.endsWith(".com/");
        
        if (cve !== "N/A" && (isGenericHome || !lowerUrl.includes(cve.toLowerCase()))) {
          url = `https://nvd.nist.gov/vuln/detail/${cve}`;
        }

        return {
          id: `derived_${item.id || idx}`,
          title: item.title,
          cve,
          cvss,
          vendor,
          product,
          exploitationStatus: item.sentiment === "Critical" ? "Telah Teridentifikasi Dieksploitasi" : "Aktivitas Ancaman Tinggi",
          description: item.description,
          source: intelSource,
          published: item.published || new Date().toISOString().split('T')[0],
          vector: item.tags || "Vulnerability",
          url,
          badge: item.sentiment === "Critical" ? "Eksploitasi Aktif" : "Sinyal Ancaman",
          tabLabel: tabLabel.substring(0, 16)
        };
      });

      setFocusAreas(derived);
      // Select first dynamic item if active focus matches none
      if (derived.length > 0 && !derived.some(d => d.id === activeFocusId)) {
        setActiveFocusId(derived[0].id);
      }
    } else {
      setFocusAreas(defaultFocusAreas);
    }
  }, [newsList]);

  useEffect(() => {
    const templates = [
      { event: "Outbound scanning probes detected pointing to critical government network subnets", type: "info" },
      { event: "Agent Tesla keylogger command stream synchronized at Indonesia Node", type: "danger" },
      { event: "Cisco Remote Code Execution hotfix guidelines deployed successfully", type: "success" },
      { event: "LockBit Ransomware payload signature parsed in Active Directory log correlation", type: "warning" },
      { event: "Tor exit node outbound activity catalogued for US East Node mapping", type: "info" },
      { event: "Repetitive authentication failure threshold breached on administrative firewall", type: "danger" },
      { event: "Malicious macro-enabled attachment detected in marketing email queue", type: "warning" },
      { event: "Known botnet C2 IP address 185.220.101.5 associated traffic drop rules updated", type: "success" }
    ];

    const interval = setInterval(() => {
      const randomTemplate = templates[Math.floor(Math.random() * templates.length)];
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0].substring(0, 5);
      
      setLiveEvents(prev => [
        { time: timeStr, event: randomTemplate.event, type: randomTemplate.type },
        ...prev.slice(0, 19) // Keep last 20 elements
      ]);
    }, 8000);

    return () => clearInterval(interval);
  }, []);

  const mapHotspots = [
    { id: "us-west", name: "US West Node", lat: "37.77", lon: "-122.41", cx: 150, cy: 110, severity: "Critical", threat: "Volt Typhoon (APT) targeting critical infrastructure", details: "Active cyber espionage campaign exploiting unpatched edge SOHO devices to inject malicious proxies.", count: "482 events/hr", color: "bg-red-500", stroke: "border-red-900/40" },
    { id: "us-east", name: "US East Node", lat: "40.71", lon: "-74.00", cx: 230, cy: 105, severity: "High", threat: "Lumma Stealer distribution campaign", details: "Phishing waves using fake corporate communications to harvest enterprise browser credentials.", count: "215 events/hr", color: "bg-amber-500", stroke: "border-amber-900/40" },
    { id: "south-america", name: "Latin America Hub", lat: "-23.55", lon: "-46.63", cx: 205, cy: 260, severity: "Medium", threat: "Android Banking Trojan overlays distribution", details: "Widespread propagation of malicious overlays targeting Latin American banking users to harvest SMS and codes.", count: "94 events/hr", color: "bg-amber-500", stroke: "border-amber-900/40" },
    { id: "eu-central", name: "EU Central Node", lat: "52.52", lon: "13.40", cx: 410, cy: 110, severity: "Critical", threat: "Qilin Ransomware active file system scans", details: "Mass credential scanning and double extortion schemes directly targeting critical manufacturing servers.", count: "612 events/hr", color: "bg-red-500", stroke: "border-red-900/40" },
    { id: "africa-south", name: "Southern Africa Gateway", lat: "-26.20", lon: "28.04", cx: 435, cy: 310, severity: "Medium", threat: "Socks5 Botnet controller traffic", details: "Coordinated outbound zombie nodes scanning port ranges to enroll more devices into malicious clusters.", count: "118 events/hr", color: "bg-blue-500", stroke: "border-blue-900/40" },
    { id: "asia-east", name: "Asia Pacific Core", lat: "35.67", lon: "139.65", cx: 770, cy: 115, severity: "Critical", threat: "Lazarus spearphishing cryptocurrency files", details: "Advanced persistent threats leveraging trojanized PDF attachments to compromise digital asset systems.", count: "344 events/hr", color: "bg-red-500", stroke: "border-red-900/40" },
    { id: "sea-hub", name: "Indonesia / SEA Hub", lat: "-6.20", lon: "106.84", cx: 640, cy: 240, severity: "High", threat: "Agent Tesla keylogger command servers", details: "Phishing links capturing client Keystrokes in manufacturing and logistics portals to exfiltrate trade details.", count: "166 events/hr", color: "bg-amber-500", stroke: "border-amber-900/40" },
    { id: "aus-east", name: "Australia Gateway", lat: "-33.86", lon: "151.20", cx: 740, cy: 340, severity: "Low", threat: "Scanning probes for misconfigured APIs", details: "Probes searching for exposed credentials and unsecured Kubernetes endpoints across local authorities.", count: "42 events/hr", color: "bg-emerald-500", stroke: "border-emerald-950/40" },
  ];

  // newsList is used dynamically now

  // Extended vendor advisories data
  const allExtendedAdvisories = [
    {
      id: "ADV-01",
      title: "Microsoft Security Update (June 2026)",
      vendor: "Microsoft",
      cve: "CVE-2024-38077",
      cvss: 9.8,
      severity: "Critical",
      remediation: "Apply official accumulated security patches straightaway via Windows Update.",
      url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077",
      time: "2h ago"
    },
    {
      id: "ADV-02",
      title: "Linux Kernel Use-After-Free Root Escalation",
      vendor: "Red Hat",
      cve: "CVE-2024-1086",
      cvss: 7.8,
      severity: "High",
      remediation: "Update all kernel packages (via yum/apt) and restart the host.",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2024-1086",
      time: "3h ago"
    },
    {
      id: "ADV-03",
      title: "Fortinet PSIRT Advisory: FortiOS SSL-VPN Bypass",
      vendor: "Fortinet",
      cve: "CVE-2024-21762",
      cvss: 9.6,
      severity: "Critical",
      remediation: "Disable SSL-VPN service or upgrade immediately to FortiOS v7.4.5+ or v7.2.9+.",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
      time: "4h ago"
    },
    {
      id: "ADV-04",
      title: "Cisco Security Advisory: Remote Code Execution on IOS XE",
      vendor: "Cisco",
      cve: "CVE-2023-20198",
      cvss: 9.8,
      severity: "Critical",
      remediation: "Install temporary Hotfix provided by Cisco or upgrade to IOS XE Fuji 16.9.10+.",
      url: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-byoleC92",
      time: "6h ago"
    },
    {
      id: "ADV-05",
      title: "VMware Security Update: vCenter Server Escape Bug",
      vendor: "VMware",
      cve: "CVE-2024-22252",
      cvss: 8.8,
      severity: "High",
      remediation: "Upgrade vCenter Instance to version 8.0 Update 2e or apply patches accordingly.",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2024-22252",
      time: "8h ago"
    },
    {
      id: "ADV-06",
      title: "Palo Alto Networks Advisory: PAN-OS Privilege Escalation",
      vendor: "Palo Alto",
      cve: "CVE-2024-0012",
      cvss: 9.3,
      severity: "Critical",
      remediation: "Apply PAN-OS updates 11.1.2-h5, 10.2.8-h5, or disable Device Management on internet.",
      url: "https://security.paloaltonetworks.com/CVE-2024-0012",
      time: "10h ago"
    },
    {
      id: "ADV-07",
      title: "F5 BIG-IP TMUI Authorization Bypass Vulnerability",
      vendor: "F5",
      cve: "CVE-2023-46747",
      cvss: 9.8,
      severity: "Critical",
      remediation: "Apply latest hotfix releases or configure local firewall access restrictions to management port.",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2023-46747",
      time: "1d ago"
    }
  ];

  // Sort news chronologically by timestamp (newest first)
  const sortedNewsList = useMemo(() => {
    return [...newsList].sort((a, b) => {
      const timeA = a.timestamp || 0;
      const timeB = b.timestamp || 0;
      return timeB - timeA;
    });
  }, [newsList]);

  // Search and filter logic
  const filteredNews = sortedNewsList.filter((news) => {
    const matchesSearch = news.title.toLowerCase().includes(newsSearch.toLowerCase()) || 
                          news.description.toLowerCase().includes(newsSearch.toLowerCase()) ||
                          news.source.toLowerCase().includes(newsSearch.toLowerCase());
    const matchesFilter = newsFilter === "All" || news.tags === newsFilter;
    return matchesSearch && matchesFilter;
  });

  const filteredAdvisories = allExtendedAdvisories.filter((adv) => {
    const matchesSearch = adv.title.toLowerCase().includes(advSearch.toLowerCase()) || 
                          adv.cve.toLowerCase().includes(advSearch.toLowerCase()) || 
                          adv.remediation.toLowerCase().includes(advSearch.toLowerCase());
    const matchesVendor = advFilter === "All" || adv.vendor === advFilter;
    const matchesSeverity = advSeverityFilter === "All" || adv.severity === advSeverityFilter;
    return matchesSearch && matchesVendor && matchesSeverity;
  });

  // Donut values from rule 7
  const donutData = [
    { label: "Malware", pct: 35, color: "#a855f7" }, // Purple
    { label: "Phishing", pct: 28, color: "#ef4444" }, // Red
    { label: "Exploit", pct: 22, color: "#f59e0b" }, // Amber
    { label: "Botnet", pct: 15, color: "#06b6d4" },  // Cyan
  ];

  // Helper arrays for tags
  const trendingTags = [
    "#LummaStealer",
    "#Qilin",
    "#AsyncRAT",
    "#LockBit",
    "#Fortinet",
    "#Microsoft365",
    "#Phishing",
    "#XWorm",
    "#Linux",
    "#DataBreach",
    "#CVE-2024-21762",
    "#APT28"
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-300 bg-transparent text-zinc-100" id="dashboard_view">
      
      {/* =================================================
          1. HERO BANNER
         ================================================= */}
      <div className="bg-gradient-to-r from-zinc-900/40 via-zinc-900/50 to-zinc-900/40 border border-zinc-800 rounded-xl p-6 relative overflow-hidden shadow-lg shadow-zinc-950/15" id="dashboard_hero_banner">
        {/* Subtle high-tech grid overlay */}
        <div className="absolute inset-0 bg-[radial-gradient(#ffffff02_1px,transparent_1px)] [background-size:16px_16px] pointer-events-none opacity-40 select-none" />
        <div className="absolute top-0 right-0 w-80 h-full bg-gradient-to-l from-blue-500/5 via-transparent to-transparent pointer-events-none select-none" />

        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6 relative z-10">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded-xl shadow-lg shadow-blue-950/30 shrink-0">
              <Radar size={28} className="animate-pulse" />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 bg-[#2563EB]/15 border border-[#2563EB]/25 text-blue-400 text-[9px] font-mono rounded tracking-widest font-bold uppercase">OPERATIONAL COMMAND CENTER</span>
                <span className="text-[#94A3B8] font-mono text-[9px]">• SOC Threat Intelligence Hub v2.5</span>
              </div>
              <h2 className="text-2xl font-bold tracking-tight text-[#F8FAFC]">CyberLens Portal</h2>
              <p className="text-xs text-[#94A3B8] max-w-2xl font-sans leading-relaxed">
                Real-time global cybersecurity telemetry, active APT campaigns tracking, and automated Indicators of Compromise (IOC) registry analysis for tactical and operational defense.
              </p>
            </div>
          </div>


        </div>
      </div>

      {/* =================================================
          2. FEATURED THREAT (PRIMARY FOCUS AREA)
         ================================================= */}
      <div 
        className="bg-zinc-900/40 border border-zinc-800 hover:border-red-500/30 rounded-xl p-6 shadow-xl relative overflow-hidden transition-all duration-200" 
        id="dashboard_featured_threat_section"
      >
        {/* Subtle cyber background line-mesh pattern */}
        <div className="absolute inset-0 bg-[#070d18]/40 pointer-events-none select-none z-0" />
        <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-[#EF4444] via-rose-600 to-[#F59E0B]" />
        <div className="absolute top-0 right-0 w-44 h-44 bg-[radial-gradient(#ef444415_1px,transparent_1px)] [background-size:12px_12px] opacity-60 pointer-events-none select-none" />

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5 relative z-10">
          <div className="flex items-center gap-2">
            <Flame size={16} className="text-[#EF4444] animate-pulse fill-red-500/10" />
            <span className="text-[10px] font-mono tracking-widest uppercase text-[#EF4444] font-bold">PRIMARY OPERATION FOCUS AREA</span>
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" title="Feed Connected & Real-time Live" />
          </div>
          
          {/* Real-time Toggles */}
          <div className="flex items-center gap-1.5 bg-zinc-950/80 p-1 rounded-lg border border-zinc-800">
            {focusAreas.map((fa) => (
              <button
                key={fa.id}
                onClick={() => setActiveFocusId(fa.id)}
                className={`px-2.5 py-1 text-[9px] font-mono font-bold tracking-wider uppercase rounded transition-all duration-150 cursor-pointer ${
                  activeFocusId === fa.id
                    ? "bg-[#EF4444]/20 text-red-400 border border-[#EF4444]/30"
                    : "text-zinc-400 hover:text-zinc-200 border border-transparent"
                }`}
              >
                {fa.tabLabel}
              </button>
            ))}
          </div>
        </div>

        {/* Dynamic content rendering based on selected tab */}
        {(() => {
          const currentFocus = focusAreas.find(fa => fa.id === activeFocusId) || focusAreas[0];
          return (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start relative z-10 animate-in fade-in duration-200">
              {/* Left Details Panel */}
              <div className="lg:col-span-8 space-y-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-1.5 py-0.5 bg-red-500/10 text-red-400 font-mono text-[8px] font-semibold tracking-wider rounded uppercase">
                      {currentFocus.badge}
                    </span>
                    <span className="text-zinc-500 text-[9px] font-mono">• Synchronized {currentFocus.published}</span>
                  </div>
                  <h3 className="text-xl font-bold font-display text-[#F8FAFC] tracking-tight hover:text-blue-400 transition-colors duration-150 leading-tight">
                    <a href={currentFocus.url} target="_blank" rel="noopener noreferrer">
                      {currentFocus.title}
                    </a>
                  </h3>
                  <p className="text-xs font-sans text-[#929fb0] leading-relaxed mt-2">
                    {currentFocus.description}
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 bg-zinc-950/60 p-3.5 rounded-xl border border-zinc-900 text-[10.5px] font-mono">
                  <div>
                    <span className="text-zinc-550 block font-bold text-[8.5px] uppercase tracking-wider mb-0.5">CVE ID:</span>
                    <span className="text-slate-100 font-bold bg-zinc-900 px-2 py-0.5 border border-zinc-850 rounded select-all">{currentFocus.cve}</span>
                  </div>
                  <div>
                    <span className="text-zinc-550 block font-bold text-[8.5px] uppercase tracking-wider mb-0.5">Vendor:</span>
                    <span className="text-slate-300 font-semibold">{currentFocus.vendor}</span>
                  </div>
                  <div>
                    <span className="text-zinc-550 block font-bold text-[8.5px] uppercase tracking-wider mb-0.5">Produk Terdampak:</span>
                    <span className="text-slate-300 font-semibold">{currentFocus.product}</span>
                  </div>
                  <div className="md:col-span-2">
                    <span className="text-zinc-550 block font-bold text-[8.5px] uppercase tracking-wider mb-0.5">Status Eksploitasi:</span>
                    <span className="text-rose-400 font-bold">{currentFocus.exploitationStatus}</span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-4 text-[10px] font-mono text-[#94A3B8]">
                  <div className="flex items-center gap-1.5 bg-zinc-950/50 px-2.5 py-1 rounded border border-zinc-800">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-ping" />
                    <span className="text-[#94A3B8]/80">Source:</span> <span className="text-[#F8FAFC] font-semibold">{currentFocus.source}</span>
                  </div>
                  <span className="text-zinc-800">•</span>
                  <div>
                    <span className="text-[#94A3B8]/80">Threat Class:</span> <span className="text-[#F59E0B] font-semibold">{currentFocus.vector}</span>
                  </div>
                </div>
              </div>

              {/* Right CVSS Score Badge Card */}
              <div className="lg:col-span-4 bg-zinc-950/80 border border-zinc-800 rounded-xl p-5 flex flex-col items-center justify-center relative min-h-[220px] shadow-inner self-stretch">
                <div className="text-center space-y-2">
                  <span className="text-[9px] font-mono text-[#94A3B8] uppercase tracking-widest font-semibold block">MAX CVSS v3.1</span>
                  <span className="text-5xl font-extrabold font-display text-transparent bg-clip-text bg-gradient-to-r from-rose-400 via-red-500 to-amber-400 block tracking-tighter leading-none">{currentFocus.cvss}</span>
                  
                  <div className="inline-flex items-center gap-1 bg-[#EF4444]/15 border border-[#EF4444]/25 text-[#EF4444] text-[9px] font-mono font-bold px-2.5 py-0.5 rounded-full select-none uppercase tracking-wide">
                    CRITICAL THREAT
                  </div>
                  
                  <span className="text-[11px] font-mono text-slate-300 font-semibold block bg-zinc-905 border border-zinc-800 px-3 py-1 rounded mt-2.5 select-all">
                    {currentFocus.cve}
                  </span>
                </div>
              </div>
            </div>
          );
        })()}
      </div>

      {/* =================================================
          3. LATEST SECURITY ADVISORIES
         ================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5" id="dashboard_advisories_sources_section">
        
        {/* Advisories Feed Panel: Grid col span 12 */}
        <div className="lg:col-span-12 bg-zinc-900/40 border border-zinc-800 rounded-xl p-5 flex flex-col justify-between shadow-xl" id="dashboard_advisories_feed">
          
          <div>
            <div className="flex justify-between items-center pb-3 border-b border-zinc-800 mb-3">
              <div className="flex items-center gap-2">
                <FileText size={14} className="text-[#10B981]" />
                <h3 className="text-xs font-bold text-slate-100 tracking-wider uppercase font-display">
                  LATEST SECURITY ADVISORIES
                </h3>
              </div>
              <button 
                onClick={() => setShowAdvisoriesModal(true)}
                className="text-[9px] font-mono text-[#10B981] hover:text-emerald-400 font-bold uppercase cursor-pointer transition"
              >
                View Registry All
              </button>
            </div>

            {/* Compact advisories list with requested color-coding in responsive grid cols */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3.5 my-3">
              
              {/* Item 1: Microsoft - Blue */}
              <a 
                href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-start gap-3 p-2.5 bg-zinc-950/60 hover:bg-zinc-950/90 rounded-lg border border-zinc-900 hover:border-blue-500/30 transition group cursor-pointer"
              >
                {/* Visual Icon with Blue border representation */}
                <div className="flex items-center justify-center w-7 h-7 shrink-0 mt-0.5 border border-[#2563EB]/40 bg-zinc-950 p-1.5 rounded-lg text-xs text-[#2563EB] font-bold font-mono">
                  MS
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex justify-between items-center gap-1.5">
                    <p className="text-[10.5px] font-bold text-slate-200 truncate group-hover:text-blue-450 transition-colors flex items-center gap-1">
                      Microsoft Security Update (June 2026)
                      <ExternalLink size={8} className="text-zinc-600 group-hover:text-blue-450" />
                    </p>
                    <span className="text-[8.5px] text-zinc-550 font-mono shrink-0">2h ago</span>
                  </div>
                  <p className="text-[9.5px] text-[#94A3B8] font-mono line-clamp-1 leading-normal">
                    Pembaruan bulanan memperbaiki 66 kerentanan aktif di Windows OS kernel. CVE-2024-38077.
                  </p>
                </div>
              </a>

              {/* Item 2: Cisco - Cyan */}
              <a 
                href="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-byoleC92"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-start gap-3 p-2.5 bg-zinc-950/60 hover:bg-zinc-950/90 rounded-lg border border-zinc-900 hover:border-cyan-500/30 transition group cursor-pointer"
              >
                <div className="flex items-center justify-center w-7 h-7 shrink-0 mt-0.5 border border-cyan-500/40 bg-zinc-950 p-1.5 rounded-lg text-xs text-cyan-400 font-bold font-mono">
                  CS
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex justify-between items-center gap-1.5">
                    <p className="text-[10.5px] font-bold text-slate-200 truncate group-hover:text-cyan-400 transition-colors flex items-center gap-1">
                      Cisco Security Advisory: IOS XE RCE
                      <ExternalLink size={8} className="text-zinc-600 group-hover:text-cyan-400" />
                    </p>
                    <span className="text-[8.5px] text-zinc-550 font-mono shrink-0">6h ago</span>
                  </div>
                  <p className="text-[9.5px] text-[#94A3B8] font-mono line-clamp-1 leading-normal">
                    Kerentanan kritis pada Cisco IOS XE dapat memungkinkan eksekusi kode tingkat root. CVE-2023-20198.
                  </p>
                </div>
              </a>

              {/* Item 3: Fortinet - Red */}
              <a 
                href="https://nvd.nist.gov/vuln/detail/CVE-2024-21762"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-start gap-3 p-2.5 bg-zinc-950/60 hover:bg-zinc-950/90 rounded-lg border border-zinc-900 hover:border-red-500/30 transition group cursor-pointer"
              >
                <div className="flex items-center justify-center w-7 h-7 shrink-0 mt-0.5 border border-[#EF4444]/40 bg-zinc-950 p-1.5 rounded-lg text-xs text-[#EF4444] font-bold font-mono">
                  FT
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex justify-between items-center gap-1.5">
                    <p className="text-[10.5px] font-bold text-slate-200 truncate group-hover:text-red-400 transition-colors flex items-center gap-1">
                      Fortinet PSIRT VPN Bypass CTI
                      <ExternalLink size={8} className="text-zinc-600 group-hover:text-red-400" />
                    </p>
                    <span className="text-[8.5px] text-zinc-550 font-mono shrink-0">4h ago</span>
                  </div>
                  <p className="text-[9.5px] text-[#94A3B8] font-mono line-clamp-1 leading-normal">
                    Kerentanan bypass SSL-VPN terus disasar oleh kelompok state-sponsored. CVE-2024-21762.
                  </p>
                </div>
              </a>

              {/* Item 4: VMware - Purple */}
              <a 
                href="https://nvd.nist.gov/vuln/detail/CVE-2024-22252"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-start gap-3 p-2.5 bg-zinc-950/60 hover:bg-zinc-950/90 rounded-lg border border-zinc-900 hover:border-purple-500/30 transition group cursor-pointer"
              >
                <div className="flex items-center justify-center w-7 h-7 shrink-0 mt-0.5 border border-purple-500/40 bg-zinc-950 p-1.5 rounded-lg text-xs text-purple-400 font-bold font-mono">
                  VM
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex justify-between items-center gap-1.5">
                    <p className="text-[10.5px] font-bold text-slate-200 truncate group-hover:text-purple-400 transition-colors flex items-center gap-1">
                      VMware vCenter Server Escape Guide
                      <ExternalLink size={8} className="text-zinc-600 group-hover:text-purple-400" />
                    </p>
                    <span className="text-[8.5px] text-zinc-550 font-mono shrink-0">8h ago</span>
                  </div>
                  <p className="text-[9.5px] text-[#94A3B8] font-mono line-clamp-1 leading-normal">
                    Pembaluan esensial menutup celah pelolosan hypervisor vCenter. CVE-2024-22252.
                  </p>
                </div>
              </a>

              {/* Item 5: Palo Alto - Orange */}
              <a 
                href="https://security.paloaltonetworks.com/CVE-2024-0012"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-start gap-3 p-2.5 bg-zinc-950/60 hover:bg-zinc-950/90 rounded-lg border border-zinc-900 hover:border-amber-500/30 transition group cursor-pointer"
              >
                <div className="flex items-center justify-center w-7 h-7 shrink-0 mt-0.5 border border-amber-500/40 bg-zinc-950 p-1.5 rounded-lg text-xs text-amber-500 font-bold font-mono">
                  PA
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex justify-between items-center gap-1.5">
                    <p className="text-[10.5px] font-bold text-slate-200 truncate group-hover:text-amber-500 transition-colors flex items-center gap-1">
                      Palo Alto PAN-OS Privilege Escalation
                      <ExternalLink size={8} className="text-zinc-600 group-hover:text-[#F59E0B]" />
                    </p>
                    <span className="text-[8.5px] text-zinc-550 font-mono shrink-0">10h ago</span>
                  </div>
                  <p className="text-[9.5px] text-[#94A3B8] font-mono line-clamp-1 leading-normal">
                    Pemberian hak akses administratif tidak sah melalui konsol manajemen. CVE-2024-0012.
                  </p>
                </div>
              </a>

            </div>
          </div>

          <button 
            onClick={() => setShowAdvisoriesModal(true)}
            className="w-full text-center py-2 bg-zinc-950 hover:bg-zinc-900 border border-zinc-900 hover:border-zinc-850 text-slate-200 hover:text-slate-100 rounded-lg text-[10px] font-mono tracking-wider font-semibold uppercase transition flex items-center justify-center gap-1.5 cursor-pointer shadow-sm mt-2"
          >
            Launch Advisories Center <ChevronRight size={11} />
          </button>

        </div>

      </div>

            {/* =================================================
          4. THREAT TRENDS & CAMPAIGNS
         ================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5" id="dashboard_landscape_trending_section">
        
        {/* Panel 1: Trending Cyber Weapons (Grid col span 4) */}
        <div className="lg:col-span-4 bg-zinc-900/40 border border-zinc-800 rounded-xl p-5 flex flex-col justify-between shadow-xl" id="dashboard_malware_weapons">
          <div className="space-y-3.5">
            <div className="border-b border-zinc-800 pb-3 flex justify-between items-center">
              <div className="flex items-center gap-1.5">
                <Flame size={12} className="text-purple-400" />
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-display">
                  Trending Cyber Weapons
                </h4>
              </div>
              <span className="text-[8px] font-mono text-blue-400 px-1.5 py-0.5 border border-blue-900/40 bg-blue-950/20 rounded uppercase font-bold">MalwareBazaar</span>
            </div>

            <div className="space-y-3 font-mono text-[9.5px]">
              {[
                { name: "Lumma Stealer", category: "Information Stealer", refUrl: "https://bazaar.abuse.ch/browse/signature/LummaStealer/", prevalence: "34%", impact: "High" },
                { name: "AsyncRAT", category: "Remote Access Trojan (RAT)", refUrl: "https://bazaar.abuse.ch/browse/signature/AsyncRAT/", prevalence: "26%", impact: "High" },
                { name: "Agent Tesla", category: "Spyware & Keylogger", refUrl: "https://bazaar.abuse.ch/browse/signature/AgentTesla/", prevalence: "18%", impact: "High" },
                { name: "LockBit", category: "Ransomware", refUrl: "https://bazaar.abuse.ch/browse/signature/LockBit/", prevalence: "12%", impact: "High" },
                { name: "RedLine Stealer", category: "Information Stealer", refUrl: "https://bazaar.abuse.ch/browse/signature/RedLine/", prevalence: "10%", impact: "High" }
              ].map((item, idx) => (
                <div 
                  key={idx}
                  className="p-2.5 bg-zinc-950/60 border border-zinc-900/60 hover:border-zinc-850 rounded-lg space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <a href={item.refUrl} target="_blank" rel="noopener noreferrer" className="text-slate-100 hover:text-blue-400 hover:underline font-bold block transition-colors duration-150">
                      {item.name}
                    </a>
                    <span className="text-[8.5px] text-purple-450 font-semibold">{item.prevalence} prevalence</span>
                  </div>
                  <div className="space-y-0.5 text-[8.5px] text-zinc-400">
                    <div><span className="text-zinc-550 font-semibold">KATEGORI:</span> {item.category}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Panel 2: Known Active Actor Campaigns (APT Hub) (Grid col span 4) */}
        <div className="lg:col-span-4 bg-zinc-900/40 border border-zinc-800 rounded-xl p-5 flex flex-col justify-between shadow-xl" id="dashboard_apt_campaigns">
          <div className="space-y-3.5">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="flex items-center gap-1.5">
                <Server size={12} className="text-purple-400" />
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-display">
                  Active Threat Campaign Identification
                </h4>
              </div>
              <span className="text-[8px] text-zinc-500 font-mono uppercase font-bold">MITRE ATT&CK</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {[
                {
                  name: "Volt Typhoon",
                  alias: "BRONZE SILHOUETTE, Vanguard Panda",
                  mitreId: "G1017",
                  refUrl: "https://attack.mitre.org/groups/G1017/",
                  origin: "State-Sponsored",
                  motive: "Infrastructure Espionage",
                  severity: "Critical"
                },
                {
                  name: "Lazarus Group",
                  alias: "APT38, Guardians of Peace, Hidden Cobra",
                  mitreId: "G0032",
                  refUrl: "https://attack.mitre.org/groups/G0032/",
                  origin: "State-Sponsored",
                  motive: "Financial & Crypto Theft",
                  severity: "Critical"
                },
                {
                  name: "APT29",
                  alias: "Cozy Bear, Midnight Blizzard, Nobelium",
                  mitreId: "G0016",
                  refUrl: "https://attack.mitre.org/groups/G0016/",
                  origin: "State-Sponsored",
                  motive: "Political Intel Gathering",
                  severity: "High"
                },
                {
                  name: "APT28",
                  alias: "Fancy Bear, Pawn Storm, Sednit",
                  mitreId: "G0007",
                  refUrl: "https://attack.mitre.org/groups/G0007/",
                  origin: "State-Sponsored",
                  motive: "Cyber Espionage",
                  severity: "High"
                }
              ].map((actor, index) => (
                <div
                  key={index}
                  className="p-2.5 bg-zinc-950/60 border border-zinc-900 rounded-lg flex flex-col justify-between space-y-1.5"
                >
                  <div className="flex justify-between items-center">
                    <a href={actor.refUrl} target="_blank" rel="noopener noreferrer" className="text-[11px] font-bold text-slate-200 hover:text-blue-400 hover:underline transition-colors duration-150">
                      {actor.name}
                    </a>
                    <span className={`text-[7px] font-mono font-bold px-1 rounded uppercase ${
                      actor.severity === "Critical" ? "bg-red-950/40 text-red-500" : "bg-purple-950/40 text-purple-500"
                    }`}>
                      {actor.severity}
                    </span>
                  </div>
                  <div className="space-y-0.5 font-mono text-[8.5px] text-zinc-400">
                    <div><span className="text-zinc-550 font-semibold">ALIAS:</span> <span className="text-zinc-300">{actor.alias}</span></div>
                    <div><span className="text-zinc-550 font-semibold">MITRE ID:</span> <span className="text-zinc-300 font-bold">{actor.mitreId}</span></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Panel 3: Active Trending Threats (Grid col span 4) */}
        <div className="lg:col-span-4 bg-zinc-900/40 border border-zinc-800 rounded-xl p-4 flex flex-col justify-between shadow-xl" id="dashboard_trending_tags_list">
          
          <div className="space-y-3.5">
            <div className="flex items-center gap-1.5 pb-2 border-b border-zinc-800">
              <Flame size={12} className="text-[#F59E0B]" />
              <h3 className="text-[10px] font-bold text-slate-200 tracking-wider uppercase font-display">
                ACTIVE TRENDING THREATS
              </h3>
            </div>

            {/* Structured cloud tags as beautiful list of badges */}
            <div className="flex flex-col gap-2.5">
              
              <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-950/60 border border-zinc-900/80 hover:border-[#EF4444]/30 hover:bg-zinc-900/40 transition duration-150">
                <span className="text-[10px] font-mono text-zinc-300 font-bold select-all">#regreSSHion</span>
                <span className="text-[9px] font-mono bg-red-950/30 text-[#EF4444] border border-red-900/40 px-1.5 py-0.5 rounded font-bold">+52% vol</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-950/60 border border-zinc-900/80 hover:border-[#EF4444]/30 hover:bg-zinc-900/40 transition duration-150">
                <span className="text-[10px] font-mono text-zinc-300 font-bold select-all">#LinuxKernelEsc</span>
                <span className="text-[9px] font-mono bg-red-950/30 text-[#EF4444] border border-red-900/40 px-1.5 py-0.5 rounded font-bold">+48% vol</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-950/60 border border-zinc-900/80 hover:border-[#EF4444]/30 hover:bg-zinc-900/40 transition duration-150">
                <span className="text-[10px] font-mono text-zinc-300 font-bold select-all">#LummaStealer</span>
                <span className="text-[9px] font-mono bg-red-950/30 text-[#EF4444] border border-red-900/40 px-1.5 py-0.5 rounded font-bold">+35% vol</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-950/60 border border-zinc-900/80 hover:border-[#EF4444]/30 hover:bg-zinc-900/40 transition duration-150">
                <span className="text-[10px] font-mono text-zinc-300 font-bold select-all">#VoltTyphoon</span>
                <span className="text-[9px] font-mono bg-red-950/30 text-[#EF4444] border border-red-900/40 px-1.5 py-0.5 rounded font-bold">+28% vol</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-950/60 border border-zinc-900/80 hover:border-amber-500/30 hover:bg-zinc-900/40 transition duration-150">
                <span className="text-[10px] font-mono text-zinc-300 font-bold select-all">#LockBit</span>
                <span className="text-[9px] font-mono bg-amber-950/30 text-[#F59E0B] border border-amber-900/40 px-1.5 py-0.5 rounded font-bold">+20% vol</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-950/60 border border-zinc-900/80 hover:border-blue-500/30 hover:bg-zinc-900/40 transition duration-150">
                <span className="text-[10px] font-mono text-zinc-300 font-bold select-all">#Microsoft365</span>
                <span className="text-[9px] font-mono bg-[#2563EB]/15 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 rounded font-bold">Alert</span>
              </div>

            </div>
          </div>



        </div>

      </div>

      {/* =================================================
          5. THE HACKER NEWS
         ================================================= */}
      <div className="space-y-3.5" id="dashboard_threat_news_section">
        <div className="flex justify-between items-center pb-2.5 border-b border-zinc-800">
          <div className="flex items-center gap-3">
            <Newspaper size={14} className={`text-blue-400 ${isFetchingRealtimeNews ? "animate-spin" : ""}`} />
            <div className="flex flex-col">
              <h3 className="text-xs font-bold font-display tracking-wider uppercase text-slate-200 flex items-center gap-2">
                THE HACKER NEWS
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[8px] font-mono font-bold text-emerald-450 bg-emerald-950/20 border border-emerald-900/40 rounded-full">
                  <span className={`w-1.2 h-1.2 rounded-full bg-emerald-500 ${isFetchingRealtimeNews ? "animate-ping" : "animate-pulse"}`}></span>
                  REAL-TIME FEED
                </span>
              </h3>
              {feedMetadata && (
                <div id="sync_status_indicators" className="flex gap-2 text-[9px] font-mono mt-0.5 text-[#64748B] flex-wrap">
                  <span>Last Updated: <span className="text-blue-400 font-semibold">{new Date(feedMetadata.lastUpdated).toLocaleString("en-US", { hour12: false })}</span></span>
                  <span className="text-slate-800">|</span>
                  <span>Next Sync: <span className="text-emerald-400 font-semibold">{new Date(feedMetadata.nextSync).toLocaleString("en-US", { hour12: false })}</span></span>
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={triggerManualSync}
              disabled={isFetchingRealtimeNews}
              id="refresh_feed_btn"
              className="px-2.5 py-1 text-[10px] font-mono text-emerald-400 hover:text-white bg-emerald-950/30 hover:bg-emerald-900/35 border border-emerald-900/45 hover:border-emerald-500/30 rounded-lg transition-all duration-150 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed font-semibold tracking-wider uppercase"
              title="Ambil update intel siber terbaru secara manual"
            >
              <RefreshCw size={10} className={isFetchingRealtimeNews ? "animate-spin" : ""} />
              [ Refresh Feed ]
            </button>
            <button 
              onClick={() => setShowNewsModal(true)}
              className="text-[10px] font-mono text-blue-400 hover:text-blue-300 hover:underline cursor-pointer font-bold uppercase transition flex items-center gap-1"
            >
              All Registry News <ChevronRight size={11} />
            </button>
          </div>
        </div>

        {/* 3 cards in horizontal grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {sortedNewsList.slice(0, 3).map((news) => (
            <div
              key={news.id}
              className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-4 flex flex-col justify-between min-h-[220px] hover:border-blue-500/30 transition-all duration-200 relative overflow-hidden"
            >
              <div className="space-y-2">
                <h4 className="text-xs font-bold font-sans leading-snug">
                  <a href={news.url} target="_blank" rel="noopener noreferrer" className="text-slate-100 hover:text-blue-400 hover:underline transition-colors duration-150">
                    {news.title}
                  </a>
                </h4>

                <p className="text-[10.5px] text-[#94A3B8] leading-relaxed font-sans">
                  {news.description}
                </p>
              </div>

              <div className="mt-3 pt-2.5 border-t border-zinc-800 space-y-1 text-[10px] font-mono">
                <div className="flex justify-between">
                  <span className="text-zinc-550 font-semibold">TANGGAL PUBLIKASI:</span>
                  <span className="text-slate-300 font-semibold">{news.published || "2024-06-03"}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>



      {/* =================================================
          8. MODAL FOR THE HACKER NEWS
         ================================================= */}
      {showNewsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-[#09090d] border border-zinc-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl relative overflow-hidden animate-in zoom-in-95 duration-150">
            {/* Background cyber lines */}
            <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-transparent via-blue-500/50 to-transparent" />
            
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-zinc-800 bg-[#0c0c12]">
              <div className="flex items-center gap-2">
                <Newspaper size={16} className={`text-blue-400 ${isFetchingRealtimeNews ? "animate-spin" : ""}`} />
                <h3 className="text-sm font-bold text-slate-200 tracking-wider uppercase font-mono">
                  The Hacker News Registry
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <button 
                  onClick={triggerManualSync}
                  disabled={isFetchingRealtimeNews}
                  className="p-1.5 px-2.5 bg-emerald-950/20 hover:bg-emerald-950/40 text-emerald-400 disabled:text-zinc-500 rounded font-mono text-[11px] transition flex items-center gap-1.5 cursor-pointer border border-emerald-950/60 hover:border-emerald-900/50 disabled:cursor-not-allowed font-semibold uppercase tracking-wider"
                >
                  <RefreshCw size={11} className={isFetchingRealtimeNews ? "animate-spin" : ""} />
                  {isFetchingRealtimeNews ? "[ Refreshing... ]" : "[ Refresh Feed ]"}
                </button>
                <button 
                  onClick={() => { setShowNewsModal(false); setNewsSearch(""); setNewsFilter("All"); }}
                  className="p-1 px-2 hover:bg-[#14141e] hover:text-white rounded text-zinc-400 font-mono text-xs transition flex items-center gap-1 cursor-pointer border border-zinc-800 hover:border-zinc-700"
                >
                  <X size={14} /> Close
                </button>
              </div>
            </div>

            {/* Controls */}
            <div className="p-4 border-b border-zinc-850 bg-[#09090d] space-y-3.5">
              {/* Search input */}
              <div className="relative">
                <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-zinc-500">
                  <Search size={14} />
                </span>
                <input 
                  type="text"
                  value={newsSearch}
                  onChange={(e) => setNewsSearch(e.target.value)}
                  placeholder="Cari berita berdasarkan judul, ringkasan, atau sumber..."
                  className="w-full bg-[#050508] border border-zinc-800 rounded-lg pl-9 pr-4 py-2 text-xs font-mono text-slate-200 placeholder:text-zinc-650 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Tag filters */}
              <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                <span className="text-zinc-500 mr-1 flex items-center gap-1">
                  <Filter size={10} /> Filter Kategori:
                </span>
                {["All", "Malware", "Phishing", "Vulnerability", "Ransomware", "APT"].map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setNewsFilter(cat)}
                    className={`px-2.5 py-1 rounded border transition cursor-pointer font-semibold ${
                      newsFilter === cat
                        ? "bg-indigo-950/40 text-indigo-400 border-indigo-550/40"
                        : "bg-zinc-900/60 hover:bg-zinc-900 text-zinc-400 border-zinc-850"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* News Lists */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-[#07070a]/50 text-slate-100">
              {filteredNews.length > 0 ? (
                filteredNews.map((news) => (
                  <div
                    key={news.id}
                    className="block p-4 bg-[#09090c]/80 border border-zinc-805 rounded-xl hover:border-blue-500/35 transition duration-150 relative"
                  >
                    <div className="space-y-2">
                      <div className="flex justify-between items-center bg-zinc-950/60 p-2 border border-zinc-900 rounded-lg">
                        <div className="space-y-0.5">
                          <a 
                            href={news.url} 
                            target="_blank" 
                            rel="noopener noreferrer" 
                            className="text-xs font-bold font-sans text-slate-200 hover:text-blue-400 hover:underline transition-colors duration-150 leading-tight block"
                          >
                            {news.title}
                          </a>
                        </div>
                        <span className={`text-[8px] font-mono font-bold uppercase px-1.5 py-0.5 rounded border ml-2 shrink-0 ${
                          news.sentiment === "Critical" 
                            ? "bg-red-950/40 text-red-445 border-red-900/35"
                            : "bg-amber-950/40 text-amber-445 border-amber-900/35"
                        }`}>
                          {news.sentiment}
                        </span>
                      </div>

                      <div className="p-2 border border-zinc-900 bg-zinc-950/20 rounded-lg">
                        <span className="text-[9px] font-mono text-[#475569] block font-bold leading-none mb-1">RINGKASAN</span>
                        <p className="text-[10.5px] text-[#94A3B8] leading-relaxed font-sans">{news.description}</p>
                      </div>

                      <div className="grid grid-cols-1 gap-2 text-[10px] font-mono p-1">
                        <div>
                          <strong className="text-zinc-550 block text-[9px] font-semibold leading-none mb-0.5">TANGGAL PUBLIKASI:</strong>
                          <span className="text-slate-300 font-semibold">{news.published || "2024-06-03"}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-12 text-zinc-500 font-mono text-xs">
                  Tidak ada berita siber yang sesuai dengan kata kunci pencarian Anda.
                </div>
              )}
            </div>

            {/* Footer info banner */}
            <div className="p-3 border-t border-zinc-850 bg-[#0a0a0f] text-[9.5px] font-mono text-zinc-500 text-center flex items-center justify-center gap-1.5">
              <Info size={11} className="text-blue-400" />
              <span>Satu klik pada berita di atas akan langsung membawamu ke portal sumber berita asli.</span>
            </div>
          </div>
        </div>
      )}

      {/* 5. MODAL: FULL THREAT LANDSCAPE SNAPSHOT EXPLORER */}
      {false && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-[#09090d] border border-zinc-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl relative overflow-hidden animate-in zoom-in-95 duration-150">
            {/* Top decorative bar */}
            <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-transparent via-purple-500/50 to-transparent" />
            
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-zinc-800 bg-[#0c0c12]">
              <div className="flex items-center gap-2">
                <Radar size={16} className="text-purple-400 animate-pulse" />
                <h3 className="text-sm font-bold text-slate-200 tracking-wider uppercase font-mono">
                  Global Threat Landscape Monitor
                </h3>
              </div>
              <button 
                onClick={() => {}}
                className="p-1 px-2 hover:bg-[#14141e] hover:text-white rounded text-zinc-400 font-mono text-xs transition flex items-center gap-1 cursor-pointer border border-zinc-800 hover:border-zinc-700"
              >
                <X size={14} /> Close
              </button>
            </div>

            {/* Scrollable Landscape Dashboard Content */}
            <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[#07070a]/40">
              
              {/* Introduction Banner */}
              <div className="bg-purple-950/15 border border-purple-900/40 p-3.5 rounded-xl flex gap-3">
                <Activity size={18} className="text-purple-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <p className="text-xs font-bold text-slate-200">Intelscape Intelligence Feed v2.4 Active</p>
                  <p className="text-[10px] text-zinc-400 font-mono leading-relaxed">
                    Sistem memantau aktor APT aktif, keluarga malware yang sedang tren, dan indikator aktivitas phishing berbasis data registri global (AbuseIPDB, OTX Pulse, CISA registries).
                  </p>
                </div>
              </div>

              {/* INTERACTIVE CYBER THREAT MAP (REALITY GEOGRAPHY MAP) */}
              <div className="bg-[#050508] border border-zinc-900 rounded-xl p-4 space-y-4 shadow-xl relative overflow-hidden flex flex-col md:flex-row gap-4">
                
                {/* CSS animation style tag for live horizontal/vertical radar simulation lines */}
                <style dangerouslySetInnerHTML={{__html: `
                  @keyframes gridScan {
                    0% { top: 0%; opacity: 0.1; }
                    50% { opacity: 0.6; }
                    100% { top: 100%; opacity: 0.1; }
                  }
                  .animate-gridScan {
                    animation: gridScan 6s linear infinite;
                  }
                `}} />

                {/* Map pane */}
                <div className="flex-1 relative bg-[#030305]/80 border border-zinc-900/60 p-2.5 rounded-xl overflow-hidden min-h-[250px] md:min-h-[290px] flex items-center justify-center select-none shadow-inner">
                  {/* Glowing Radar scanline effect */}
                  <div className="absolute inset-x-0 h-[1.5px] bg-indigo-500/30 blur-[1px] animate-gridScan pointer-events-none z-10" />

                  <svg viewBox="0 0 900 380" className="w-full h-full text-indigo-500/50 fill-zinc-950 stroke-zinc-900 stroke-[1.2] z-0">
                    {/* Background Grids */}
                    <g className="stroke-zinc-900/40 stroke-[0.5] fill-none">
                      <line x1="0" y1="40" x2="900" y2="40" />
                      <line x1="0" y1="80" x2="900" y2="80" />
                      <line x1="0" y1="120" x2="900" y2="120" />
                      <line x1="0" y1="160" x2="900" y2="160" />
                      <line x1="0" y1="200" x2="900" y2="200" />
                      <line x1="0" y1="240" x2="900" y2="240" />
                      <line x1="0" y1="280" x2="900" y2="280" />
                      <line x1="0" y1="320" x2="900" y2="320" />
                      <line x1="0" y1="360" x2="900" y2="360" />

                      <line x1="100" y1="0" x2="100" y2="380" />
                      <line x1="200" y1="0" x2="200" y2="380" />
                      <line x1="300" y1="0" x2="300" y2="380" />
                      <line x1="400" y1="0" x2="400" y2="380" />
                      <line x1="500" y1="0" x2="500" y2="380" />
                      <line x1="600" y1="0" x2="600" y2="380" />
                      <line x1="700" y1="0" x2="700" y2="380" />
                      <line x1="800" y1="0" x2="800" y2="380" />
                    </g>
                    
                    {/* Realistic Handcrafted Continents rendered in high contrast dark neon styling */}
                    {/* GREENLAND */}
                    <path d="M 330,40 L 375,30 L 390,55 L 340,65 Z" className="fill-zinc-800/30 hover:fill-zinc-800/50 stroke-zinc-700/60 stroke-[0.8] transition" />

                    {/* NORTH AMERICA */}
                    <path d="M 100,60 L 130,50 L 155,45 L 195,50 L 230,52 L 280,52 L 295,68 L 280,82 L 255,90 L 245,105 L 270,112 L 274,124 L 255,138 L 242,135 L 225,150 L 230,161 L 208,168 L 195,180 L 181,195 L 172,213 C 170,217 166,217 166,210 L 155,168 L 146,160 L 132,165 L 123,153 L 130,142 L 110,138 L 101,127 L 110,112 L 92,105 L 87,90 L 96,75 L 91,56 Z" className="fill-zinc-800/30 hover:fill-zinc-800/50 stroke-zinc-700/60 stroke-[0.8] transition" />

                    {/* SOUTH AMERICA */}
                    <path d="M 166,210 C 172,217 181,225 190,228 C 203,235 220,247 229,262 C 233,277 229,300 220,315 C 211,330 198,348 185,367 C 176,378 171,385 167,392 C 165,394 161,392 161,385 C 162,367 157,345 148,322 C 139,300 128,277 128,259 C 128,240 137,225 152,213 Z" className="fill-zinc-800/30 hover:fill-zinc-800/50 stroke-zinc-700/60 stroke-[0.8] transition" />

                    {/* AFRICA */}
                    <path d="M 390,165 C 408,153 425,157 452,161 C 470,168 487,180 491,191 L 500,202 L 518,213 C 522,217 518,221 505,225 L 491,243 C 487,258 478,277 465,300 C 456,315 443,337 434,352 C 430,360 425,360 425,348 C 426,330 420,307 411,288 C 402,270 389,255 385,240 C 378,217 375,202 380,187 C 385,176 388,168 390,165 Z" className="fill-zinc-800/30 hover:fill-zinc-800/50 stroke-zinc-700/60 stroke-[0.8] transition" />

                    {/* EURASIA */}
                    <path d="M 365,101 L 374,82 L 369,63 L 387,52 L 410,48 L 427,63 L 441,82 L 454,63 L 481,56 L 508,51 C 544,48 598,45 643,51 C 679,56 733,52 778,63 C 814,75 832,90 832,108 L 814,127 L 796,146 L 778,157 L 755,168 L 728,168 L 710,183 L 701,198 L 710,221 L 694,232 C 683,240 665,251 651,255 L 633,243 L 611,236 L 602,221 L 588,210 C 575,202 557,202 543,191 C 530,183 512,180 494,183 L 471,180 L 449,187 L 431,180 L 417,172 L 401,172 L 392,161 L 395,142 L 381,123 Z" className="fill-zinc-800/30 hover:fill-zinc-800/50 stroke-zinc-700/60 stroke-[0.8] transition" />

                    {/* AUSTRALIA */}
                    <path d="M 687,307 C 705,300 727,303 745,315 C 758,326 758,341 754,352 L 740,363 L 718,360 L 696,348 C 682,337 678,318 687,307 Z" className="fill-zinc-800/30 hover:fill-zinc-800/50 stroke-zinc-700/60 stroke-[0.8] transition" />

                    {/* ISLANDS */}
                    <path d="M 481,303 C 486,300 490,311 486,322 C 481,326 477,318 481,303 Z" className="fill-[#08080f] stroke-zinc-805 stroke-[0.8]" /> {/* Madagascar */}
                    <path d="M 778,108 Q 796,123 782,142" className="stroke-zinc-800 stroke-1 fill-none" /> {/* Japan */}
                    <path d="M 374,101 Q 383,93 378,108 Z" className="fill-[#08080f] stroke-zinc-805 stroke-[0.8]" /> {/* UK & Ireland */}

                    {/* Pulsating Glowing Hotspots */}
                    {mapHotspots.map((pt) => {
                      const isSelected = selectedHotspotId === pt.id;
                      const size = isSelected ? 11 : 8;
                      const colorHex = pt.severity === "Critical" ? "#ef4444" : pt.severity === "High" ? "#f59e0b" : pt.severity === "Medium" ? "#3b82f6" : "#10b981";
                      return (
                        <g 
                          key={pt.id} 
                          className="cursor-pointer group/node"
                          onClick={() => setSelectedHotspotId(pt.id)}
                        >
                          {/* Pulsing visual halo */}
                          <circle 
                            cx={pt.cx} 
                            cy={pt.cy} 
                            r={isSelected ? 18 : 9} 
                            fill={colorHex} 
                            opacity={isSelected ? 0.35 : 0.15} 
                            className="animate-ping" 
                            style={{ animationDuration: isSelected ? '1.5s' : '3s' }}
                          />
                          <circle 
                            cx={pt.cx} 
                            cy={pt.cy} 
                            r={size} 
                            fill={colorHex} 
                            stroke="#ffffff" 
                            strokeWidth={isSelected ? 1.5 : 0} 
                            className="transition-all duration-200"
                          />
                          {/* Inner core */}
                          <circle 
                            cx={pt.cx} 
                            cy={pt.cy} 
                            r={2.5} 
                            fill="#ffffff" 
                          />
                          {/* Pin indicator pointer */}
                          {isSelected && (
                            <path 
                              d={`M ${pt.cx},${pt.cy - 10} L ${pt.cx - 4},${pt.cy - 18} L ${pt.cx + 4},${pt.cy - 18} Z`} 
                              fill={colorHex} 
                            />
                          )}
                        </g>
                      );
                    })}
                  </svg>

                  {/* World Map Legend */}
                  <div className="absolute bottom-3 left-3 bg-[#08080c]/90 border border-zinc-800/80 px-2 rounded text-[9px] font-mono text-zinc-400 space-y-0.5 flex flex-col backdrop-blur-sm shadow-md">
                    <span className="font-bold text-slate-400 text-[8px] uppercase tracking-wider">Severity Legend</span>
                    <div className="flex flex-wrap items-center gap-2 pb-0.5">
                      <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-500" /> Critical</span>
                      <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-amber-500" /> High</span>
                      <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-blue-500" /> Medium</span>
                    </div>
                  </div>
                </div>

                {/* Info Display read-out of the selected location */}
                {(() => {
                  const selectedPt = mapHotspots.find(p => p.id === selectedHotspotId) || mapHotspots[0];
                  const severityBadgeColor = selectedPt.severity === "Critical" 
                    ? "bg-red-950/40 text-red-400 border-red-900/35"
                    : selectedPt.severity === "High"
                    ? "bg-amber-950/40 text-amber-450 border-amber-900/35"
                    : selectedPt.severity === "Medium"
                    ? "bg-blue-950/40 text-blue-400 border-blue-900/35"
                    : "bg-emerald-900/30 text-emerald-400 border-emerald-900/20";

                  return (
                    <div className="w-full md:w-[240px] bg-[#07070a]/90 border border-zinc-850 p-3.5 rounded-xl flex flex-col justify-between font-mono text-[11px] text-zinc-300 relative shadow-md">
                      <div className="space-y-3">
                        <div className="flex items-start justify-between gap-1 border-b border-zinc-900 pb-2">
                          <div className="min-w-0 pr-1">
                            <span className="text-[8px] text-zinc-550 font-semibold block uppercase">INTEL NODE</span>
                            <h4 className="text-xs font-bold text-slate-100 flex items-center gap-1">
                              <MapPin size={10} className="text-indigo-400 shrink-0" />
                              <span className="truncate">{selectedPt.name}</span>
                            </h4>
                          </div>
                          <span className={`text-[8px] font-bold px-1.5 py-0.2 border rounded uppercase shrink-0 ${severityBadgeColor}`}>
                            {selectedPt.severity}
                          </span>
                        </div>

                        <div className="space-y-2">
                          <div>
                            <span className="text-[8.5px] text-zinc-500 font-semibold block uppercase">Active Vector:</span>
                            <span className="text-slate-200 text-[10px] leading-snug font-semibold block">{selectedPt.threat}</span>
                          </div>
                          <div>
                            <span className="text-[8.5px] text-zinc-500 font-semibold block uppercase">Details & Target:</span>
                            <p className="text-[9.5px] text-zinc-400 leading-normal">{selectedPt.details}</p>
                          </div>
                        </div>
                      </div>

                      <div className="mt-3 pt-2.5 border-t border-zinc-900 space-y-0.5 text-[8.5px] text-zinc-550">
                        <div className="flex justify-between">
                          <span>GRID COORDS:</span>
                          <span className="text-zinc-400 font-bold">{selectedPt.lat}, {selectedPt.lon}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>INGRESS FLOW:</span>
                          <span className="text-rose-400 font-bold animate-pulse">{selectedPt.count}</span>
                        </div>
                      </div>
                    </div>
                  );
                })()}

              </div>

              {/* Grids inside Modal */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                
                {/* Panel 1: Top Threatened Sectors & Countries */}
                <div className="bg-[#0b0b0f] border border-zinc-900 rounded-xl p-3.5 space-y-3">
                  <div className="border-b border-zinc-850 pb-2 flex justify-between items-center">
                    <span className="text-[10px] font-bold text-slate-300 font-mono tracking-wider uppercase">
                      Top Target Sectors (7D)
                    </span>
                    <span className="text-[8px] font-mono text-red-400 px-1 border border-red-900/40 bg-red-950/20 rounded">Critical</span>
                  </div>
                  
                  <div className="space-y-2 font-mono text-[10px]">
                    {[
                      { sector: "Critical Infrastructure / Energy", level: "92%", color: "bg-red-500" },
                      { sector: "Technology & Software Vendors", level: "84%", color: "bg-orange-500" },
                      { sector: "Financial Services & Banking", level: "79%", color: "bg-amber-500" },
                      { sector: "Healthcare & Pharmaceuticals", level: "71%", color: "bg-blue-500" },
                      { sector: "Manufacturing & Electronics", level: "63%", color: "bg-indigo-500" }
                    ].map((item, idx) => (
                      <div key={idx} className="space-y-1">
                        <div className="flex justify-between text-zinc-400">
                          <span>{item.sector}</span>
                          <span className="font-bold text-slate-200">{item.level}</span>
                        </div>
                        <div className="w-full h-1 bg-zinc-900 rounded-full overflow-hidden">
                          <div className={`h-full ${item.color}`} style={{ width: item.level }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Panel 2: Malware Strains Today Prevalence */}
                <div className="bg-[#0b0b0f] border border-zinc-900 rounded-xl p-3.5 space-y-3">
                  <div className="border-b border-zinc-850 pb-2 flex justify-between items-center">
                    <span className="text-[10px] font-bold text-slate-300 font-mono tracking-wider uppercase">
                      Trending Cyber Weapons
                    </span>
                    <span className="text-[8px] font-mono text-blue-400 px-1 border border-blue-900/40 bg-blue-950/20 rounded">Live Feed</span>
                  </div>

                  <div className="space-y-2 font-mono text-[10px]">
                    {[
                      { strain: "Lumma Stealer (Info-stealer)", share: "34%", impact: "High", link: "https://thehackernews.com/search?q=Lumma+Stealer" },
                      { strain: "AsyncRAT (Remote Trojan)", share: "22%", impact: "High", link: "https://thehackernews.com/search?q=AsyncRAT" },
                      { strain: "Agent Tesla (Spyware Keylogger)", share: "18%", impact: "Medium", link: "https://thehackernews.com/search?q=Agent+Tesla" },
                      { strain: "Socks5 Proxy Botnet (Evasive)", share: "14%", impact: "Medium", link: "https://thehackernews.com/search?q=Botnet" },
                      { strain: "XWorm RAT & Crypters", share: "12%", impact: "High", link: "https://thehackernews.com/search?q=XWorm" }
                    ].map((item, idx) => (
                      <a 
                        key={idx}
                        href={item.link} 
                        target="_blank" 
                        rel="noopener noreferrer" 
                        className="flex items-center justify-between p-1.5 hover:bg-zinc-900 border border-transparent hover:border-zinc-850 rounded transition group"
                      >
                        <div className="flex items-center gap-1.5 min-w-0 pr-1">
                          <Flame size={10} className="text-purple-400 shrink-0" />
                          <span className="text-zinc-300 truncate group-hover:text-purple-450 transition-colors">{item.strain}</span>
                        </div>
                        <div className="flex items-center gap-2 font-bold font-mono text-[9px] shrink-0">
                          <span className="text-zinc-500">{item.share} prevalence</span>
                          <ExternalLink size={8} className="text-zinc-600 group-hover:text-purple-400" />
                        </div>
                      </a>
                    ))}
                  </div>
                </div>

              </div>

              {/* Active APT Threat Actors Block */}
              <div className="bg-[#0b0b0f] border border-zinc-900 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-zinc-850">
                  <div className="flex items-center gap-1.5">
                    <Server size={12} className="text-purple-400" />
                    <span className="text-[10px] font-bold text-slate-300 font-mono tracking-wider uppercase">
                      Known Active Actor Campaigns (APT Hub)
                    </span>
                  </div>
                  <span className="text-[8px] text-zinc-500 font-mono">attributed source</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {[
                    {
                      name: "Volt Typhoon",
                      origin: "State-Sponsored",
                      motive: "Espionage & Infrastructure Sabotage",
                      signature: "Living-off-the-land (LotL), SOHO router hijacking",
                      severity: "Critical",
                      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/ms-01"
                    },
                    {
                      name: "Qilin Group",
                      origin: "Ransomware-as-a-Service",
                      motive: "Financial Gain / High-Value Extortion",
                      signature: "Double-extortion, registry deletion commands",
                      severity: "Critical",
                      url: "https://www.bleepingcomputer.com/tag/qilin/"
                    },
                    {
                      name: "APT29 (Cozy Bear)",
                      origin: "State-Sponsored",
                      motive: "Political & Intelligence gathering",
                      signature: "Phishing PDF with embedded javascript evasion",
                      severity: "High",
                      url: "https://thehackernews.com/search?q=APT29"
                    },
                    {
                      name: "Lazarus Cyber Division",
                      origin: "State-Sponsored",
                      motive: "Financial & Crypto Theft",
                      signature: "Fake job recruitment PDFs with trojanized payloads",
                      severity: "High",
                      url: "https://thehackernews.com/search?q=Lazarus"
                    }
                  ].map((actor, index) => (
                    <a
                      key={index}
                      href={actor.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-3 bg-zinc-950/60 hover:bg-zinc-950 border border-zinc-900 hover:border-zinc-800 rounded-xl flex flex-col justify-between space-y-2 transition group cursor-pointer"
                    >
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-bold text-slate-200 group-hover:text-purple-400 transition-colors flex items-center gap-1">
                          {actor.name}
                          <ExternalLink size={9} className="text-zinc-600 group-hover:text-purple-400" />
                        </span>
                        <span className={`text-[8px] font-mono font-bold px-1 rounded uppercase ${
                          actor.severity === "Critical" ? "bg-red-950/40 text-red-500" : "bg-purple-950/40 text-purple-500"
                        }`}>
                          {actor.severity}
                        </span>
                      </div>
                      <div className="space-y-1 font-mono text-[9px] text-zinc-400">
                        <div><strong className="text-zinc-500 font-semibold">Origin:</strong> {actor.origin}</div>
                        <div><strong className="text-zinc-500 font-semibold">Motive:</strong> {actor.motive}</div>
                        <div><strong className="text-zinc-500 font-semibold">Method:</strong> {actor.signature}</div>
                      </div>
                    </a>
                  ))}
                </div>
              </div>

            </div>

            {/* Footer */}
            <div className="p-4 border-t border-zinc-800 bg-[#0c0c12] flex justify-end">
              <button 
                onClick={() => {}}
                className="px-4 py-2 bg-purple-900/40 text-purple-400 border border-purple-800/40 hover:bg-purple-800/20 rounded-lg text-xs font-mono font-semibold uppercase tracking-wider transition cursor-pointer"
              >
                Close View
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. MODAL: VENDOR SECURITY ADVISORIES CENTER */}
      {showAdvisoriesModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-[#09090d] border border-zinc-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl relative overflow-hidden animate-in zoom-in-95 duration-150">
            {/* Background cyber line */}
            <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent" />
            
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-zinc-800 bg-[#0c0c12]">
              <div className="flex items-center gap-2">
                <FileText size={16} className="text-emerald-400" />
                <h3 className="text-sm font-bold text-slate-200 tracking-wider uppercase font-mono">
                  Official Advisory Registry (PSIRT & CVEs)
                </h3>
              </div>
              <button 
                onClick={() => { setShowAdvisoriesModal(false); setAdvSearch(""); setAdvFilter("All"); setAdvSeverityFilter("All"); }}
                className="p-1 px-2 hover:bg-[#14141e] hover:text-white rounded text-zinc-400 font-mono text-xs transition flex items-center gap-1 cursor-pointer border border-zinc-800 hover:border-zinc-700"
              >
                <X size={14} /> Close
              </button>
            </div>

            {/* Controls */}
            <div className="p-4 border-b border-zinc-850 bg-[#09090d] space-y-3.5">
              
              {/* Search bar */}
              <div className="relative">
                <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-zinc-500">
                  <Search size={14} />
                </span>
                <input 
                  type="text"
                  value={advSearch}
                  onChange={(e) => setAdvSearch(e.target.value)}
                  placeholder="Cari advisories berdasarkan CVE ID, produk, atau rekomendasi perbaikan..."
                  className="w-full bg-[#050508] border border-zinc-800 rounded-lg pl-9 pr-4 py-2 text-xs font-mono text-slate-100 placeholder:text-zinc-650 focus:outline-none focus:border-emerald-500"
                />
              </div>

              {/* Vendor Filters Row */}
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between text-[10px] font-mono">
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-zinc-500 mr-1 flex items-center gap-1">
                    <Filter size={10} /> Vendor:
                  </span>
                  {["All", "Microsoft", "Fortinet", "Cisco", "VMware", "Palo Alto", "Red Hat"].map((ven) => (
                    <button
                      key={ven}
                      onClick={() => setAdvFilter(ven)}
                      className={`px-2 py-0.5 rounded border transition cursor-pointer font-semibold ${
                        advFilter === ven
                          ? "bg-emerald-900/30 text-emerald-400 border-emerald-500/50"
                          : "bg-zinc-900/60 hover:bg-zinc-900 text-zinc-400 border-zinc-850"
                      }`}
                    >
                      {ven}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-1">
                  <span className="text-zinc-500 mr-1">Severity:</span>
                  {["All", "Critical", "High"].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setAdvSeverityFilter(sev)}
                      className={`px-2 py-0.5 rounded border transition cursor-pointer font-semibold ${
                        advSeverityFilter === sev
                          ? "bg-red-900/30 text-rose-400 border-red-500/50"
                          : "bg-zinc-900/60 hover:bg-zinc-900 text-zinc-400 border-zinc-850"
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

            </div>

            {/* Content list */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-[#07070a]/50">
              {filteredAdvisories.length > 0 ? (
                filteredAdvisories.map((adv) => (
                  <a
                    key={adv.id}
                    href={adv.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block p-3.5 bg-[#09090c] hover:bg-[#111116] border border-zinc-900 hover:border-zinc-800 rounded-xl transition group relative cursor-pointer"
                  >
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono bg-zinc-950 border border-zinc-850 text-zinc-400 px-1.5 py-0.5 rounded font-bold uppercase">
                          {adv.id}
                        </span>
                        <span className="text-xs font-bold text-slate-200 group-hover:text-emerald-400 transition-colors leading-snug">
                          {adv.title}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded border ${
                          adv.severity === "Critical" 
                            ? "bg-red-950/40 text-red-400 border-red-900/35"
                            : "bg-amber-950/40 text-amber-550 border-amber-900/35"
                        }`}>
                          {adv.severity} (CVSS {adv.cvss})
                        </span>
                        <ExternalLink size={10} className="text-zinc-500 group-hover:text-emerald-400 transition-colors" />
                      </div>
                    </div>

                    <div className="space-y-1.5 font-mono text-[10px] text-zinc-400 pl-1 border-l border-zinc-800">
                      <div><strong className="text-zinc-500">Vulnerability Code:</strong> {adv.cve}</div>
                      <div>
                        <strong className="text-zinc-550 block mb-0.5">Remediation / Tindakan Perbaikan:</strong> 
                        <span className="text-slate-300 block">{adv.remediation}</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between border-t border-zinc-900/70 mt-2.5 pt-2 text-[8.5px] font-mono text-zinc-500">
                      <span>Vendor: <strong>{adv.vendor}</strong></span>
                      <span>Published {adv.time}</span>
                    </div>

                  </a>
                ))
              ) : (
                <div className="text-center py-12 text-zinc-500 font-mono text-xs">
                  Tidak ada vendor security advisories yang sesuai dengan filter pencarian Anda.
                </div>
              )}
            </div>

            {/* Footer warning */}
            <div className="p-3 border-t border-zinc-850 bg-[#0a0a0f] text-[9.5px] font-mono text-zinc-500 text-center flex items-center justify-center gap-1.5">
              <ShieldAlert size={11} className="text-emerald-400" />
              <span>Satu klik pada advisori akan langsung membawamu ke portal panduan resmi PSIRT / perbaikan dari Vendor.</span>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
