import type { Metadata } from "next";
import type { ReactNode } from "react";
import { IBM_Plex_Mono, IBM_Plex_Sans, IBM_Plex_Sans_Condensed } from "next/font/google";

import "./globals.css";

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["300", "400", "500"],
  variable: "--font-plex-mono",
  display: "swap",
});

const plexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-plex-sans",
  display: "swap",
});

const plexSansCond = IBM_Plex_Sans_Condensed({
  subsets: ["latin"],
  weight: ["500", "600", "700"],
  variable: "--font-plex-sans-cond",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Chio Evidence Console",
  description: "Offline evidence viewer for Chio bundle reviews.",
};

export default function RootLayout({ children }: { children: ReactNode }): JSX.Element {
  const fontVars = `${plexMono.variable} ${plexSans.variable} ${plexSansCond.variable}`;
  return (
    <html lang="en" className={fontVars}>
      <body>
        <div id="root">{children}</div>
      </body>
    </html>
  );
}
