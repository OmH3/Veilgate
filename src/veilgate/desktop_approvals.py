"""Desktop approval companion. Run in the human's interactive desktop session.

This is a local development UI, not an authentication boundary. Protect the
database and reviewer environment separately for adversarial deployments.
"""

import argparse
import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path


class ApprovalStore:
    def __init__(self, path: Path, timeout: int = 120):
        self.path = path.resolve()
        self.timeout = timeout

    @contextmanager
    def connect(self):
        # Never create a second, empty database due to a wrong working directory.
        conn = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=0.5)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def deadline(self, row):
        summary = json.loads(row["summary_json"])
        if "expires_at" in summary:
            return datetime.fromisoformat(summary["expires_at"]).astimezone(UTC)
        return datetime.fromisoformat(row["requested_at"]).astimezone(UTC) + timedelta(seconds=self.timeout)

    def pending(self):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status='PENDING' ORDER BY requested_at"
            ).fetchall()
        return [dict(row) for row in rows if self.deadline(row) > datetime.now(UTC)]

    def decide(self, row, decision):
        if decision not in ("APPROVED", "APPROVED_AND_SAVED", "DENIED"):
            raise ValueError("Unknown decision")
        if self.deadline(row) <= datetime.now(UTC):
            return False
        # Compare the exact displayed snapshot, and permit only PENDING -> decision.
        # A competing watcher/dashboard cannot overwrite an already resolved call.
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if self.deadline(row) <= datetime.now(UTC):
                return False
            result = conn.execute(
                "UPDATE approvals SET status=?, decided_at=?, decided_by=?, learned_grant=? "
                "WHERE approval_id=? AND status='PENDING' AND session_id=? "
                "AND qualified_ref=? AND summary_json=? AND requested_at=?",
                (decision, datetime.now(UTC).isoformat(), "desktop_reviewer",
                 row["qualified_ref"] if decision == "APPROVED_AND_SAVED" else None,
                 row["approval_id"], row["session_id"], row["qualified_ref"],
                 row["summary_json"], row["requested_at"]),
            )
            return result.rowcount == 1


def run_ui(store, preview=False):
    import tkinter as tk
    from tkinter import messagebox, ttk
    from tkinter.scrolledtext import ScrolledText

    root = tk.Tk()
    root.title("Veilgate approval companion")
    root.geometry("760x550")
    root.minsize(620, 420)
    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Veilgate · Human approval", font=("Segoe UI", 17, "bold")).pack(anchor="w")
    ttk.Label(frame, text=f"Database: {store.path}", wraplength=710).pack(anchor="w", pady=8)
    status = tk.StringVar(value="Starting…")
    ttk.Label(frame, textvariable=status, wraplength=710).pack(anchor="w", pady=6)
    details = ScrolledText(frame, height=16, wrap="word")
    details.pack(fill="both", expand=True)
    details.configure(state="disabled")
    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=(14, 0))
    current = None
    last_id = None
    preview_done = False
    preview_row = {
        "approval_id": "preview-only", "session_id": "preview", "qualified_ref": "demo.read",
        "requested_at": datetime.now(UTC).isoformat(),
        "summary_json": json.dumps({"args": {"message": "Preview only. No tool executes."}}),
        "reason": "UI_PREVIEW",
    }

    def display(row):
        details.configure(state="normal")
        details.delete("1.0", "end")
        if row:
            summary = json.loads(row["summary_json"])
            args = summary.get("args", summary.get("args_sample", {}))
            sample_note = "\nLegacy request: arguments below may be truncated.\n" if "args" not in summary else ""
            details.insert("end", f"Tool: {row['qualified_ref']}\nRequest: {row['approval_id']}\n"
                           f"Reason: {row.get('reason', '')}\n{sample_note}\n"
                           + json.dumps(args, indent=2, ensure_ascii=False))
        else:
            details.insert("end", "Waiting for guarded tool calls.\nKeep this companion running on your desktop.")
        details.configure(state="disabled")
        for button in action_buttons:
            button.configure(state="normal" if row else "disabled")

    def decide(decision):
        nonlocal current, last_id, preview_done
        row = current
        if row is None:
            return
        if decision == "APPROVED_AND_SAVED" and not messagebox.askyesno(
            "Confirm persistent tool permission",
            f"Allow future calls to {row['qualified_ref']} with different arguments?\n\n"
            "The current gateway saves a tool-wide grant, not an argument-scoped grant.\n"
            "Choose No to use Allow once instead.", parent=root, default="no",
        ):
            return
        try:
            accepted = True if preview else store.decide(row, decision)
            if not accepted:
                messagebox.showinfo("Request no longer pending", "The request expired, changed, or was already resolved.", parent=root)
            if preview:
                preview_done = True
            current = None
            last_id = None
            display(None)
            status.set(f"{'Preview: ' if preview else ''}{decision if accepted else 'No decision applied'}")
        except (sqlite3.Error, ValueError, OSError) as exc:
            messagebox.showerror("Approval not saved", str(exc), parent=root)

    action_buttons = []
    for label, decision in (("Allow once", "APPROVED"), ("Allow always…", "APPROVED_AND_SAVED"), ("Deny", "DENIED")):
        button = ttk.Button(buttons, text=label, command=lambda value=decision: decide(value))
        button.pack(side="left", padx=(0, 10))
        action_buttons.append(button)

    def close():
        if current is not None and not preview:
            try:
                store.decide(current, "DENIED")
            except (sqlite3.Error, ValueError, OSError):
                pass  # Failure to save denial never becomes an approval.
        root.destroy()

    def poll():
        nonlocal current, last_id
        try:
            rows = ([preview_row] if not preview_done else []) if preview else store.pending()
            row = rows[0] if rows else None
            current = row
            row_id = (row["approval_id"], row["summary_json"]) if row else None
            if row_id != last_id:
                display(row)
                last_id = row_id
                if row:
                    root.deiconify()
                    root.lift()
                    root.bell()
                    root.attributes("-topmost", True)
                    root.after(1500, lambda: root.attributes("-topmost", False))
            if row:
                seconds = max(0, int((store.deadline(row) - datetime.now(UTC)).total_seconds()))
                status.set(f"{'PREVIEW · ' if preview else ''}{len(rows)} pending · expires in {seconds}s")
            elif not preview_done:
                status.set("Connected · waiting for approval requests")
        except (sqlite3.Error, ValueError, KeyError, OSError) as exc:
            current = None
            last_id = None
            display(None)
            status.set(f"Cannot read requests: {exc}")
        root.after(500, poll)

    root.protocol("WM_DELETE_WINDOW", close)
    root.bind("<Escape>", lambda event: decide("DENIED"))
    display(None)
    poll()
    root.mainloop()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True, help="Exact gateway approval database")
    parser.add_argument("--timeout", type=int, default=120, help="Legacy request timeout; match gateway setting")
    parser.add_argument("--preview", action="store_true", help="Show a fake request without reading/writing the database")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        run_ui(ApprovalStore(args.db, args.timeout), args.preview)
    except ImportError as exc:
        parser.exit(1, f"Tkinter is required: {exc}\n")
    except Exception as exc:
        parser.exit(1, f"Desktop companion failed: {exc}. Run it from your logged-in desktop session.\n")


if __name__ == "__main__":
    main()
