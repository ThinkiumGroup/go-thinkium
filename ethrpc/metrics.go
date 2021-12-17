package ethrpc

type Gauge interface {
	Snapshot() Gauge
	Update(int64)
	Dec(int64)
	Inc(int64)
	Value() int64
}
