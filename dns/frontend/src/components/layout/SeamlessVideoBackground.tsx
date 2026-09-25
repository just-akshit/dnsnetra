"use client";

import { useRef, useEffect, useState } from "react";

interface SeamlessVideoBackgroundProps {
  src: string;
  transitionDuration?: number;
}

const SeamlessVideoBackground = ({ src, transitionDuration = 1.5 }: SeamlessVideoBackgroundProps) => {
  const video1Ref = useRef<HTMLVideoElement>(null);
  const video2Ref = useRef<HTMLVideoElement>(null);
  const [activeVideo, setActiveVideo] = useState(1);

  useEffect(() => {
    const v1 = video1Ref.current;
    const v2 = video2Ref.current;
    if (!v1 || !v2) return;

    let animationFrameId: number;

    const checkTime = () => {
      // If v1 is playing and nearing the end
      if (activeVideo === 1 && v1.duration) {
        if (v1.duration - v1.currentTime <= transitionDuration) {
          v2.currentTime = 0;
          v2.play().catch(e => console.log(e));
          setActiveVideo(2);
        }
      } 
      // If v2 is playing and nearing the end
      else if (activeVideo === 2 && v2.duration) {
        if (v2.duration - v2.currentTime <= transitionDuration) {
          v1.currentTime = 0;
          v1.play().catch(e => console.log(e));
          setActiveVideo(1);
        }
      }

      animationFrameId = requestAnimationFrame(checkTime);
    };

    animationFrameId = requestAnimationFrame(checkTime);

    return () => cancelAnimationFrame(animationFrameId);
  }, [activeVideo, transitionDuration]);

  return (
    <div className="absolute inset-0 w-full h-full bg-black overflow-hidden pointer-events-none z-0">
      {/* 
        To prevent dipping to black during crossfade, we don't fade the old video out.
        Instead, we fade the new video IN on top of the old video.
        Whichever video is active gets a higher z-index and fades to full opacity.
        The inactive video stays underneath until the transition finishes.
      */}
      <video
        ref={video1Ref}
        autoPlay
        muted
        playsInline
        className="absolute inset-0 w-full h-full object-cover ease-in-out"
        style={{ 
          opacity: activeVideo === 1 ? 0.8 : 0, 
          transition: `opacity ${transitionDuration}s`,
          zIndex: activeVideo === 1 ? 20 : 10 
        }}
      >
        <source src={src} type="video/mp4" />
      </video>
      <video
        ref={video2Ref}
        muted
        playsInline
        className="absolute inset-0 w-full h-full object-cover ease-in-out"
        style={{ 
          opacity: activeVideo === 2 ? 0.8 : 0, 
          transition: `opacity ${transitionDuration}s`,
          zIndex: activeVideo === 2 ? 20 : 10
        }}
      >
        <source src={src} type="video/mp4" />
      </video>
    </div>
  );
};

export default SeamlessVideoBackground;
