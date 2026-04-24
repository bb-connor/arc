// React's JSX types do not expose the motion-path SVG elements (animateMotion,
// mpath). These shims let strict TypeScript accept them on standard SVG.

import "react";

declare module "react" {
  namespace JSX {
    interface IntrinsicElements {
      animateMotion: React.SVGProps<SVGElement> & {
        dur?: string;
        repeatCount?: string | number;
        rotate?: string;
        begin?: string;
      };
      mpath: React.SVGProps<SVGElement> & {
        href?: string;
      };
    }
  }
}
