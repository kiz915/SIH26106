/**
 * ThreatLens - SIH26106 Frontend Constants
 * Obsidian Cyber-Intelligence Design Tokens & Engine Presets
 */

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const MAX_FILE_SIZE_MB = 15;
export const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

export const RISK_TIERS = {
  'LOW RISK': {
    color: '#00e676',
    bg: 'rgba(0, 230, 118, 0.12)',
    border: 'rgba(0, 230, 118, 0.35)',
    label: 'Low Risk',
    badge: 'CLEAN / VERIFIED',
    icon: 'ShieldCheck',
    gradient: 'from-emerald-500 to-green-400',
    glow: '0 0 15px rgba(0, 230, 118, 0.3)',
  },
  'MEDIUM RISK': {
    color: '#ffa000',
    bg: 'rgba(255, 160, 0, 0.12)',
    border: 'rgba(255, 160, 0, 0.35)',
    label: 'Medium Risk',
    badge: 'SUSPICIOUS ANOMALY',
    icon: 'AlertTriangle',
    gradient: 'from-amber-500 to-yellow-400',
    glow: '0 0 15px rgba(255, 160, 0, 0.3)',
  },
  'HIGH RISK': {
    color: '#ff4b2b',
    bg: 'rgba(255, 75, 43, 0.14)',
    border: 'rgba(255, 75, 43, 0.4)',
    label: 'High Risk',
    badge: 'HIGH THREAT DETECTED',
    icon: 'ShieldAlert',
    gradient: 'from-rose-500 to-red-500',
    glow: '0 0 20px rgba(255, 75, 43, 0.35)',
  },
  'CRITICAL RISK': {
    color: '#ff1744',
    bg: 'rgba(255, 23, 68, 0.2)',
    border: 'rgba(255, 23, 68, 0.55)',
    label: 'Critical Risk',
    badge: 'CRITICAL ATTACK / BEC',
    icon: 'Skull',
    gradient: 'from-red-700 to-red-500',
    glow: '0 0 25px rgba(255, 23, 68, 0.5)',
  },
};

export const AUTH_STATUS_CONFIG = {
  PASS: {
    color: '#00e5ff',
    bg: 'rgba(0, 229, 255, 0.15)',
    border: 'rgba(0, 229, 255, 0.4)',
    label: 'Pass',
    icon: 'CheckCircle',
  },
  FAIL: {
    color: '#ff4b2b',
    bg: 'rgba(255, 75, 43, 0.2)',
    border: 'rgba(255, 75, 43, 0.5)',
    label: 'Fail',
    icon: 'XCircle',
  },
  NONE: {
    color: '#849396',
    bg: 'rgba(132, 147, 150, 0.15)',
    border: 'rgba(132, 147, 150, 0.3)',
    label: 'None',
    icon: 'MinusCircle',
  },
  UNKNOWN: {
    color: '#ffa000',
    bg: 'rgba(255, 160, 0, 0.15)',
    border: 'rgba(255, 160, 0, 0.35)',
    label: 'Unknown',
    icon: 'HelpCircle',
  },
};

export const SEVERITY_COLORS = {
  LOW: { color: '#00e676', bg: 'rgba(0, 230, 118, 0.12)', border: 'rgba(0, 230, 118, 0.3)' },
  MEDIUM: { color: '#ffa000', bg: 'rgba(255, 160, 0, 0.12)', border: 'rgba(255, 160, 0, 0.3)' },
  HIGH: { color: '#ff4b2b', bg: 'rgba(255, 75, 43, 0.15)', border: 'rgba(255, 75, 43, 0.4)' },
  CRITICAL: { color: '#ff1744', bg: 'rgba(255, 23, 68, 0.2)', border: 'rgba(255, 23, 68, 0.5)' },
};

export const IP_TYPE_CONFIG = {
  public: { color: '#00e5ff', label: 'Public Internet Node', icon: 'Globe' },
  rfc1918: { color: '#818cf8', label: 'Private RFC1918 LAN', icon: 'Lock' },
  loopback: { color: '#849396', label: 'Local Loopback (127.0.0.1)', icon: 'RotateCcw' },
  'link-local': { color: '#c084fc', label: 'Link-Local Network', icon: 'Link' },
  documentation: { color: '#ffa000', label: 'Test / Documentation Block', icon: 'FileText' },
  reserved: { color: '#64748b', label: 'IANA Reserved Range', icon: 'Shield' },
};

export const NAV_LINKS = [
  { href: '/', label: 'Command Center', icon: 'LayoutDashboard', badge: 'HUD' },
  { href: '/analyze', label: 'Analyze EML', icon: 'Upload' },
  { href: '/cases', label: 'Case Vault', icon: 'FolderArchive' },
  { href: '/ml-intelligence', label: 'AI/ML Studio', icon: 'BrainCircuit', badge: 'AI' },
  { href: '/blockchain', label: 'Ledger Custody', icon: 'Blocks', badge: 'CHAIN' },
  { href: '/map', label: 'Geo-Relay Map', icon: 'Map' },
  { href: '/status', label: 'Engine Nodes', icon: 'Activity' },
];

export const BLOCKCHAIN_NETWORK = {
  name: 'ThreatLens Forensic Proof-of-Custody Ledger',
  network: 'Ethereum / Polygon Forensic Subnet (Private Consortium)',
  chainId: 26106,
  contractAddress: '0x8f2d93e18a4a75b26106c138d821e901a5f973dc',
  merkleStandard: 'RFC-6962 Certificate Transparency / NIST SP 800-86',
};
