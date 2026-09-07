import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import Navbar from '@/components/layout/Navbar';
import Footer from '@/components/layout/Footer';
import InteractiveBackground from '@/components/common/InteractiveBackground';
import { ThemeProvider } from '@/context/ThemeContext';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
});

export const metadata = {
  title: 'ThreatLens — Email Forensics & Phishing Analysis',
  description: 'Upload an .eml file to analyze headers, authentication, and risk signals for phishing and business email compromise.',
  keywords: ['email forensics', 'threat intelligence', 'phishing detection', 'cybersecurity', 'SIH2026'],
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`light ${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="antialiased min-h-screen selection:bg-cyan-500/30 selection:text-cyan-200 transition-colors duration-300">
        <ThemeProvider>
          {/* Interactive Dynamic Background with Animated Constellation Canvas */}
          <InteractiveBackground />

          <div className="relative z-10 flex flex-col min-h-screen">
            <Navbar />
            <main className="flex-1 pt-16">
              {children}
            </main>
            <Footer />
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
