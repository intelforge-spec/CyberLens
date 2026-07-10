import fs from "fs";
import path from "path";
import crypto from "crypto";
import bcrypt from "bcryptjs";

const DB_FILE = path.join(process.cwd(), "cyberlens-db.json");

// Types
export interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: "Admin" | "Analyst" | "Viewer";
  createdAt: string;
}

export interface Integration {
  id: string;
  name: string;
  apiKeyEncrypted: string;
  status: "Connected" | "Disconnected" | "Invalid API Key" | "Rate Limited";
  lastTestTime: string | null;
}

export interface AuditLog {
  id: string;
  username: string;
  role: string;
  action: string;
  ipAddress: string;
  details: string;
  timestamp: string;
}

// Encryption Config
const ALGORITHM = "aes-256-cbc";
const ENCRYPTION_KEY = crypto.scryptSync(process.env.ENCRYPTION_KEY || "cyberlens-enterprise-secret-key-salt-9871!", "salt", 32);
const IV_LENGTH = 16;

export function encrypt(text: string): string {
  if (!text) return "";
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

export function decrypt(text: string): string {
  if (!text) return "";
  try {
    const parts = text.split(":");
    if (parts.length < 2) return "";
    const iv = Buffer.from(parts.shift()!, "hex");
    const encryptedText = Buffer.from(parts.join(":"), "hex");
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText);
    const finalBuffer = Buffer.concat([decrypted, decipher.final()]);
    return finalBuffer.toString("utf8");
  } catch (error) {
    console.error("Encryption decryption failed:", error);
    return "";
  }
}

// Initial default seed integrations
const DEFAULT_INTEGRATIONS: Integration[] = [
  { id: "abuseipdb", name: "AbuseIPDB IP Reputation", apiKeyEncrypted: "", status: "Disconnected", lastTestTime: null },
  { id: "alienvault", name: "AlienVault OTX Threat Feed", apiKeyEncrypted: "", status: "Disconnected", lastTestTime: null },
  { id: "malwarebazaar", name: "MalwareBazaar Binary Repository", apiKeyEncrypted: "", status: "Disconnected", lastTestTime: null },
  { id: "urlhaus", name: "URLHaus Phishing Directory", apiKeyEncrypted: "", status: "Disconnected", lastTestTime: null },
  { id: "virustotal", name: "VirusTotal Global Reputation", apiKeyEncrypted: "", status: "Disconnected", lastTestTime: null }
];

export class CyberLensDB {
  private data: {
    users: User[];
    integrations: Integration[];
    auditLogs: AuditLog[];
    investigations: any[];
    feedNews?: any[];
    feedMetadata?: {
      lastUpdated: string;
      nextSync: string;
    };
  } = {
    users: [],
    integrations: [],
    auditLogs: [],
    investigations: [],
    feedNews: [],
    feedMetadata: {
      lastUpdated: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
      nextSync: new Date().toISOString()
    }
  };

  constructor() {
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const fileContent = fs.readFileSync(DB_FILE, "utf8");
        this.data = JSON.parse(fileContent);
        // Ensure standard fields exist
        if (!this.data.users) this.data.users = [];
        if (!this.data.integrations || this.data.integrations.length === 0) {
          this.data.integrations = DEFAULT_INTEGRATIONS;
        }
        if (!this.data.auditLogs) this.data.auditLogs = [];
        if (!this.data.feedNews) this.data.feedNews = [];
        if (!this.data.feedMetadata) {
          this.data.feedMetadata = {
            lastUpdated: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
            nextSync: new Date().toISOString()
          };
        }
        if (!this.data.investigations) {
          this.data.investigations = [];
        } else {
          // Clean up any duplicate records dynamically on load
          const seenIds = new Set<string>();
          this.data.investigations = this.data.investigations.filter(item => {
            if (!item || !item.id) return false;
            if (seenIds.has(item.id)) return false;
            seenIds.add(item.id);
            return true;
          });
        }
      } else {
        this.seedDefaults();
      }
    } catch (error) {
      console.error("Failed to load CyberLens database, seeding defaults:", error);
      this.seedDefaults();
    }
  }

  private save() {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), "utf8");
    } catch (error) {
      console.error("Failed to save CyberLens database:", error);
    }
  }

  private seedDefaults() {
    // Generate default admin account
    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync("admin123", salt);
    
    this.data.users = [
      {
        id: "usr_admin",
        username: "admin",
        passwordHash,
        role: "Admin",
        createdAt: new Date().toISOString()
      },
      // Seed default Analyst & Viewer for testing convenience
      {
        id: "usr_analyst",
        username: "analyst",
        passwordHash: bcrypt.hashSync("analyst123", salt),
        role: "Analyst",
        createdAt: new Date().toISOString()
      },
      {
        id: "usr_viewer",
        username: "viewer",
        passwordHash: bcrypt.hashSync("viewer123", salt),
        role: "Viewer",
        createdAt: new Date().toISOString()
      }
    ];

    this.data.integrations = DEFAULT_INTEGRATIONS;
    this.data.auditLogs = [
      {
        id: "log_init",
        username: "SYSTEM",
        role: "System",
        action: "DATABASE_INITIALIZATION",
        ipAddress: "127.0.0.1",
        details: "CyberLens secure database initialization completed. Default Admin and system roles loaded.",
        timestamp: new Date().toISOString()
      }
    ];
    this.data.investigations = [];

    this.save();
    console.log("Database initialized and default Admin/system roles seeded gracefully.");
  }

  // User Operations
  getUsers(): Omit<User, "passwordHash">[] {
    return this.data.users.map(({ id, username, role, createdAt }) => ({
      id,
      username,
      role,
      createdAt
    }));
  }

  findUser(username: string): User | undefined {
    return this.data.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  }

  createUser(username: string, passwordPlain: string, role: "Admin" | "Analyst" | "Viewer"): User {
    const existing = this.findUser(username);
    if (existing) {
      throw new Error(`Username "${username}" already exists.`);
    }

    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(passwordPlain, salt);
    const newUser: User = {
      id: "usr_" + crypto.randomBytes(4).toString("hex"),
      username,
      passwordHash,
      role,
      createdAt: new Date().toISOString()
    };

    this.data.users.push(newUser);
    this.save();
    return newUser;
  }

  updateUserPassword(id: string, newPasswordPlain: string) {
    const user = this.data.users.find(u => u.id === id);
    if (!user) {
      throw new Error("User index reference invalid.");
    }

    const salt = bcrypt.genSaltSync(10);
    user.passwordHash = bcrypt.hashSync(newPasswordPlain, salt);
    this.save();
  }

  deleteUser(id: string, operatorUsername: string) {
    const userIndex = this.data.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new Error("User lookup target not found.");
    }
    
    const userToDelete = this.data.users[userIndex];
    if (userToDelete.username === operatorUsername) {
      throw new Error("An operator cannot remove their own profile.");
    }

    if (userToDelete.username === "admin") {
      throw new Error("Cannot delete primary system admin user.");
    }

    this.data.users.splice(userIndex, 1);
    this.save();
  }

  // Integration Operations
  getIntegrations(): Integration[] {
    return this.data.integrations;
  }

  updateIntegrationKey(id: string, plainKey: string) {
    const integration = this.data.integrations.find(i => i.id === id);
    if (!integration) {
      throw new Error("Integration setting node not found.");
    }

    integration.apiKeyEncrypted = plainKey ? encrypt(plainKey) : "";
    integration.status = plainKey ? "Connected" : "Disconnected";
    integration.lastTestTime = new Date().toISOString();
    this.save();
  }

  updateIntegrationStatus(id: string, status: Integration["status"]) {
    const integration = this.data.integrations.find(i => i.id === id);
    if (integration) {
      integration.status = status;
      integration.lastTestTime = new Date().toISOString();
      this.save();
    }
  }

  getDecryptedKey(id: string): string {
    const integration = this.data.integrations.find(i => i.id === id);
    if (!integration || !integration.apiKeyEncrypted) return "";
    return decrypt(integration.apiKeyEncrypted);
  }

  // Audit Logs Operations
  getAuditLogs(): AuditLog[] {
    return this.data.auditLogs;
  }

  deleteAuditLogs(ids: string[]): void {
    this.data.auditLogs = this.data.auditLogs.filter(log => !ids.includes(log.id));
    this.save();
  }

  addAuditLog(username: string, role: string, action: string, ipAddress: string, details: string) {
    const newLog: AuditLog = {
      id: "log_" + crypto.randomBytes(8).toString("hex"),
      username,
      role,
      action,
      ipAddress: ipAddress || "127.0.0.1",
      details,
      timestamp: new Date().toISOString()
    };

    this.data.auditLogs.unshift(newLog);
    // Trim audit logs to last 500 for lightweight storage
    if (this.data.auditLogs.length > 500) {
      this.data.auditLogs = this.data.auditLogs.slice(0, 500);
    }
    this.save();
  }

  // Investigations Persistence
  getInvestigations(): any[] {
    return this.data.investigations;
  }

  addInvestigation(record: any) {
    if (!record || !record.id) return;
    
    // Prevent duplicate entries representing the same record from being inserted
    const exists = this.data.investigations.some(item => item && item.id === record.id);
    if (exists) return;

    this.data.investigations.unshift(record);
    if (this.data.investigations.length > 200) {
      this.data.investigations.splice(200); // Truncating in-place to keep references stable
    }
    this.save();
  }

  setInvestigations(records: any[]) {
    this.data.investigations = records;
    this.save();
  }

  // Threat Feed Operations
  getFeedNews(): any[] {
    return this.data.feedNews || [];
  }

  setFeedNews(news: any[]) {
    this.data.feedNews = news;
    this.save();
  }

  getFeedMetadata() {
    return this.data.feedMetadata || {
      lastUpdated: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
      nextSync: new Date().toISOString()
    };
  }

  setFeedMetadata(metadata: { lastUpdated: string; nextSync: string }) {
    this.data.feedMetadata = metadata;
    this.save();
  }
}

export const dbInstance = new CyberLensDB();
