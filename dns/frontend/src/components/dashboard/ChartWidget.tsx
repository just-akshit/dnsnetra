import React from "react";
import { DashboardWidget, DashboardWidgetProps } from "./DashboardWidget";

export interface ChartWidgetProps extends Omit<DashboardWidgetProps, "children"> {
  height?: number | string;
  children?: React.ReactNode;
}

export const ChartWidget: React.FC<ChartWidgetProps> = ({
  height = 240,
  children,
  className,
  ...props
}) => {
  return (
    <DashboardWidget className={className} {...props}>
      <div style={{ height, width: "100%" }} className="w-full">
        {children}
      </div>
    </DashboardWidget>
  );
};

export default ChartWidget;
