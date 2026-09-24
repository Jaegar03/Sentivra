"use client";

import { useState, type ReactNode } from "react";
import { ChartColumn, Table2 } from "lucide-react";

import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export interface TableRowData {
  label: string;
  value: number | string;
}

/**
 * A chart with a table-view twin. The table is the WCAG-clean equivalent:
 * every value in the chart is reachable without hovering (dataviz rule:
 * tooltips enhance, never gate).
 */
export function ChartCard({
  title,
  description,
  rows,
  valueLabel = "Count",
  children,
}: {
  title: string;
  description?: ReactNode;
  rows: TableRowData[];
  valueLabel?: string;
  children: ReactNode;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description ? <CardDescription>{description}</CardDescription> : null}
        <CardAction>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-pressed={asTable}
            aria-label={asTable ? "Show chart" : "Show as table"}
            title={asTable ? "Show chart" : "Show as table"}
            onClick={() => setAsTable((v) => !v)}
          >
            {asTable ? <ChartColumn /> : <Table2 />}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {asTable ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-muted-foreground">
                <th className="py-1.5 font-medium">Label</th>
                <th className="py-1.5 text-right font-medium">{valueLabel}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.label} className="border-b last:border-0">
                  <td className="py-1.5">{r.label}</td>
                  <td className="py-1.5 text-right tabular">{r.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          children
        )}
      </CardContent>
    </Card>
  );
}
