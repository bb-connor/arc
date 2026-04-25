"use client";

import { BundleProvider } from "@/components/BundleProvider";
import { Console } from "@/components/Console";

export default function HomePage(): JSX.Element {
  return (
    <BundleProvider>
      <Console />
    </BundleProvider>
  );
}
