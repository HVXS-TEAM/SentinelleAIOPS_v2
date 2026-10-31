import React from 'react';

export type IconSize = 'xs' | 'sm' | 'md' | 'lg' | 'xl' | number;

export interface IconProps extends React.HTMLAttributes<HTMLSpanElement> {
  name: string;
  size?: IconSize;
  fill?: boolean;
  weight?: 100 | 200 | 300 | 400 | 500 | 600 | 700;
  grade?: -25 | 0 | 200;
  opticalSize?: 20 | 24 | 40 | 48;
  className?: string;
}

const SIZE_MAP: Record<Exclude<IconSize, number>, string> = {
  xs: '16px',
  sm: '18px',
  md: '20px',
  lg: '24px',
  xl: '32px',
};

export const Icon: React.FC<IconProps> = ({
  name,
  size = 'md',
  fill = false,
  weight = 400,
  grade = 0,
  opticalSize = 24,
  className = '',
  style,
  ...rest
}) => {
  const pixelSize = typeof size === 'number' ? `${size}px` : SIZE_MAP[size];

  const fontVariationSettings = `'FILL' ${fill ? 1 : 0}, 'wght' ${weight}, 'GRAD' ${grade}, 'opsz' ${opticalSize}`;

  return (
    <span
      className={`material-symbols-outlined select-none inline-flex items-center justify-center leading-none ${className}`}
      style={{
        fontSize: pixelSize,
        width: pixelSize,
        height: pixelSize,
        fontVariationSettings,
        ...style,
      }}
      aria-hidden={rest['aria-label'] ? undefined : true}
      {...rest}
    >
      {name}
    </span>
  );
};

export default Icon;
