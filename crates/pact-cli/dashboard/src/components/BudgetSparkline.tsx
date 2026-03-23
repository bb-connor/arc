import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

interface BudgetSparklineProps {
  data: { time: string; cost: number }[]
}

/**
 * Formats a minor-unit integer for display in the sparkline tooltip.
 * Uses integer arithmetic only -- no float conversion for monetary values.
 */
function formatCost(value: number): string {
  const major = Math.floor(value / 100)
  const minor = (value % 100).toString().padStart(2, '0')
  return `$${major}.${minor}`
}

/**
 * Renders a Recharts 2 AreaChart sparkline for cost over time.
 * Shows "No cost data" placeholder when data array is empty.
 */
export function BudgetSparkline({ data }: BudgetSparklineProps) {
  if (data.length === 0) {
    return <div className="sparkline-placeholder">No cost data</div>
  }

  return (
    <ResponsiveContainer width="100%" height={60}>
      <AreaChart data={data} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
        <Area
          type="monotone"
          dataKey="cost"
          stroke="#6366f1"
          fill="#e0e7ff"
          strokeWidth={1.5}
          dot={false}
        />
        <XAxis dataKey="time" hide />
        <YAxis hide />
        <Tooltip
          formatter={(value) => [formatCost(value as number), 'Cost']}
          labelFormatter={(label) => String(label)}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
