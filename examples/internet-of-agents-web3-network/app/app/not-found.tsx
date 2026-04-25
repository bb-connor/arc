export default function NotFound(): JSX.Element {
  return (
    <div style={{ padding: 24, fontFamily: "var(--mono)", color: "#d5dbe3" }}>
      <h1 style={{ fontSize: 18 }}>not found</h1>
      <p>The requested resource was not found in the Chio Evidence Console.</p>
    </div>
  );
}
