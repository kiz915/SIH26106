'use client';

/**
 * Minimal skeleton loader component using Tailwind animate-pulse.
 * Used for loading states across the dashboard.
 */

export function Skeleton({ className = '', width, height, rounded = 'rounded-md' }) {
  return (
    <div
      className={`animate-pulse bg-[var(--surface-container-high)] ${rounded} ${className}`}
      style={{ width, height }}
    />
  );
}

export function SkeletonText({ lines = 3, className = '' }) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton
          key={i}
          className="h-3"
          width={i === lines - 1 ? '60%' : '100%'}
        />
      ))}
    </div>
  );
}

export function SkeletonCard({ className = '' }) {
  return (
    <div className={`glass-card p-4 space-y-3 ${className}`}>
      <div className="flex items-center gap-3">
        <Skeleton className="w-10 h-10" rounded="rounded-xl" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-3 w-2/3" />
          <Skeleton className="h-2 w-1/3" />
        </div>
      </div>
      <SkeletonText lines={2} />
    </div>
  );
}

export function SkeletonTableRow({ cols = 5, className = '' }) {
  return (
    <div className={`flex items-center gap-4 p-4 ${className}`}>
      {Array.from({ length: cols }).map((_, i) => (
        <Skeleton
          key={i}
          className="h-4"
          width={i === 0 ? '120px' : i === cols - 1 ? '80px' : '100px'}
        />
      ))}
    </div>
  );
}

export default Skeleton;
