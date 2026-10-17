import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ResultTable } from "../components/ResultTable";

describe("ResultTable", () => {
  it("renders hostile values as plain text, never as HTML", () => {
    const evil = '<img src=x onerror="alert(1)">';
    const { container } = render(
      <ResultTable rows={[{ CUST_ID: 1001, FULL_NAME: evil, AADHAAR: "XXXXXXXX2222", NOTE: null }]} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(evil)).toBeInTheDocument();
  });

  it("styles masked values and right-aligns numbers", () => {
    render(<ResultTable rows={[{ BALANCE: 12500000, PAN: "XXXXXX234F" }]} />);
    expect(screen.getByText("XXXXXX234F")).toHaveClass("masked");
    expect(screen.getByText("1,25,00,000")).toHaveClass("num");
  });

  it("renders nothing for no rows", () => {
    const { container } = render(<ResultTable rows={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
