import { describe, beforeEach, afterEach, expect, it } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import userEvent from "@testing-library/user-event";
import FilterInput, { type FilterChangeDetails } from "./FilterInput";
import { createStoredList } from "./storage";

const historyStore = createStoredList("pipe-lion.filter-history", 8);

type HarnessResult = {
  getLastChange: () => FilterChangeDetails | null;
};

function renderFilterInput(): HarnessResult {
  let lastChange: FilterChangeDetails | null = null;

  function Harness() {
    const [text, setText] = useState("");
    return (
      <FilterInput
        id="display-filter"
        label="Display filter"
        value={text}
        onFilterChange={(details) => {
          lastChange = details;
          setText(details.text);
        }}
      />
    );
  }

  render(<Harness />);

  return {
    getLastChange: () => lastChange,
  };
}

describe("FilterInput", () => {
  beforeEach(() => {
    historyStore.clear();
  });

  afterEach(() => {
    cleanup();
  });

  it("surfaces field suggestions and supports keyboard navigation", async () => {
    const user = userEvent.setup();
    renderFilterInput();

    const input = screen.getByLabelText(/display filter/i);
    await user.click(input);
    await user.type(input, "pro");

    await waitFor(() => {
      expect(input).toHaveAttribute("aria-expanded", "true");
    });

    const options = screen.getAllByRole("option");
    expect(options[0]).toHaveTextContent(/protocol/i);

    await user.keyboard("{ArrowDown}{Enter}");
    expect(input).toHaveValue("protocol ");

    const operatorOption = await screen.findByRole("option", {
      name: /==/i,
    });
    expect(operatorOption).toBeInTheDocument();
  });

  it("marks the input invalid and exposes error details for malformed filters", async () => {
    const user = userEvent.setup();
    const { getLastChange } = renderFilterInput();

    const input = screen.getAllByLabelText(/display filter/i)[0];
    await user.click(input);
    await user.type(input, "protocol ==");

    expect(await screen.findByTestId("filter-error-highlight")).toBeVisible();
    expect(input).toHaveAttribute("aria-invalid", "true");

    const lastChange = getLastChange();
    expect(lastChange?.errorMessage).toMatch(/comparison operator/i);
  });
});
