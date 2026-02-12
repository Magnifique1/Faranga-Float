from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import secrets
import subprocess
import ssl
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = ROOT / "uploads"
PHONE_REGEX = re.compile(r"^\+250\d{9}$")
TOPUP_PHONE_REGEX = re.compile(r"^250\d{9}$")
SESSION_COOKIE = "session_id"
MONEY_QUANT = Decimal("0.01")
SESSION_TIMEOUT_MINUTES = 5
SESSION_TIMEOUT_DISABLED = True

MYSQL_HOST = "146.190.113.67"
MYSQL_USER = "magnifique"
MYSQL_PASSWORD = "msN7qyp9zbPn4g_LZ"
MYSQL_DB = "faranga_float"


class MySQLError(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_str() -> str:
    return utc_now().strftime("%Y-%m-%d %H:%M:%S")


def today_local() -> date:
    return datetime.now().date()


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return digest.hex(), salt.hex()


def verify_password(password: str, password_hash: str, salt_hex: str) -> bool:
    digest, _ = hash_password(password, bytes.fromhex(salt_hex))
    return secrets.compare_digest(digest, password_hash)


def to_money(value: object) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Invalid amount.")
    if amount <= 0:
        raise ValueError("Amount must be greater than 0.")
    return amount.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)


def money_to_float(value: Decimal) -> float:
    return float(value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP))


def _sql_literal(value: object) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float, Decimal)):
        return str(value)
    if isinstance(value, datetime):
        return f"'{value.strftime('%Y-%m-%d %H:%M:%S')}'"
    if isinstance(value, date):
        return f"'{value.isoformat()}'"
    text = str(value)
    text = text.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{text}'"


def _format_query(query: str, params: tuple | list | None) -> str:
    if not params:
        return query
    parts = query.split("?")
    if len(parts) - 1 != len(params):
        raise ValueError("Query placeholder count does not match params")
    out: list[str] = [parts[0]]
    for value, suffix in zip(params, parts[1:]):
        out.append(_sql_literal(value))
        out.append(suffix)
    return "".join(out)


def _run_mysql(sql: str, *, use_db: bool = True, with_headers: bool = True) -> str:
    cmd = [
        "mysql",
        "-h",
        MYSQL_HOST,
        "-u",
        MYSQL_USER,
        f"-p{MYSQL_PASSWORD}",
        "--batch",
        "--raw",
    ]
    if not with_headers:
        cmd.append("--skip-column-names")
    if use_db:
        cmd.extend(["-D", MYSQL_DB])
    cmd.extend(["-e", sql])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr or result.stdout).strip() or "MySQL command failed"
        raise MySQLError(error)
    return result.stdout


def _parse_rows(output: str) -> list[dict]:
    raw = output.strip("\n")
    if not raw:
        return []
    lines = raw.splitlines()
    if not lines:
        return []
    columns = lines[0].split("\t")
    rows: list[dict] = []
    for line in lines[1:]:
        values = line.split("\t")
        row = {}
        for idx, column in enumerate(columns):
            value = values[idx] if idx < len(values) else None
            row[column] = None if value in {"\\N", "NULL"} else value
        rows.append(row)
    return rows


def select_all(query: str, params: tuple | list | None = None) -> list[dict]:
    sql = _format_query(query, tuple(params) if params is not None else ())
    output = _run_mysql(sql, use_db=True, with_headers=True)
    return _parse_rows(output)


def select_one(query: str, params: tuple | list | None = None) -> dict | None:
    rows = select_all(query, params)
    return rows[0] if rows else None


def execute(query: str, params: tuple | list | None = None) -> tuple[int, int]:
    sql = _format_query(query, tuple(params) if params is not None else ())
    script = f"{sql.rstrip(';')}; SELECT ROW_COUNT() AS row_count, LAST_INSERT_ID() AS last_id;"
    output = _run_mysql(script, use_db=True, with_headers=False)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return 0, 0
    last = lines[-1]
    parts = last.split("\t")
    row_count = int(parts[0]) if parts and parts[0].lstrip("-").isdigit() else 0
    last_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return row_count, last_id


def init_db() -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    _run_mysql(
        f"CREATE DATABASE IF NOT EXISTS {MYSQL_DB} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
        use_db=False,
        with_headers=False,
    )

    execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            account_type VARCHAR(20) NOT NULL,
            name VARCHAR(255) NULL,
            email VARCHAR(255) NOT NULL,
            phone VARCHAR(20) NULL,
            national_id_path VARCHAR(500) NULL,
            business_name VARCHAR(255) NULL,
            business_email VARCHAR(255) NULL,
            business_reg_no VARCHAR(255) NULL,
            business_reg_path VARCHAR(500) NULL,
            password_hash VARCHAR(255) NOT NULL,
            password_salt VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            UNIQUE KEY users_email_idx (email)
        ) ENGINE=InnoDB
        """
    )

    execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id VARCHAR(64) PRIMARY KEY,
            user_id INT NOT NULL,
            created_at DATETIME NOT NULL,
            last_active_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB
        """
    )

    def table_exists(table_name: str) -> bool:
        row = select_one(
            """
            SELECT TABLE_NAME
            FROM information_schema.tables
            WHERE table_schema = ? AND table_name = ?
            """,
            (MYSQL_DB, table_name),
        )
        return row is not None

    def column_exists(table_name: str, column_name: str) -> bool:
        row = select_one(
            """
            SELECT COLUMN_NAME
            FROM information_schema.columns
            WHERE table_schema = ? AND table_name = ? AND column_name = ?
            """,
            (MYSQL_DB, table_name, column_name),
        )
        return row is not None

    # One-time typo migration: receipients -> recipients.
    if table_exists("receipients") and not table_exists("recipients"):
        execute("RENAME TABLE receipients TO recipients")
    if table_exists("as_receipients") and not table_exists("as_recipients"):
        execute("RENAME TABLE as_receipients TO as_recipients")
    if table_exists("airtime_scheduels") and not table_exists("airtime_schedules"):
        execute("RENAME TABLE airtime_scheduels TO airtime_schedules")

    execute(
        """
        CREATE TABLE IF NOT EXISTS recipients (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(255) NOT NULL,
            phone VARCHAR(20) NOT NULL,
            carrier VARCHAR(50) NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            deleted_at DATETIME NULL,
            INDEX recipients_user_idx (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB
        """
    )

    execute(
        """
        CREATE TABLE IF NOT EXISTS funds_recipients (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(255) NOT NULL,
            phone VARCHAR(20) NOT NULL,
            carrier VARCHAR(50) NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            deleted_at DATETIME NULL,
            INDEX funds_recipients_user_idx (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB
        """
    )

    execute(
        """
        CREATE TABLE IF NOT EXISTS airtime_schedules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            as_date DATE NOT NULL,
            as_desc TEXT NOT NULL,
            as_total_recipients INT NOT NULL,
            as_total_amount DECIMAL(14,2) NOT NULL,
            approved TINYINT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            deleted_at DATETIME NULL,
            INDEX schedules_user_idx (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB
        """
    )

    execute(
        """
        CREATE TABLE IF NOT EXISTS as_recipients (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            as_id INT NOT NULL,
            recipient_id INT NOT NULL,
            airtime_amount DECIMAL(14,2) NOT NULL,
            created_at DATETIME NOT NULL,
            deleted_at DATETIME NULL,
            INDEX as_recipients_user_idx (user_id),
            INDEX as_recipients_as_id_idx (as_id),
            INDEX as_recipients_recipient_id_idx (recipient_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (as_id) REFERENCES airtime_schedules(id),
            FOREIGN KEY (recipient_id) REFERENCES recipients(id)
        ) ENGINE=InnoDB
        """
    )

    execute(
        """
        CREATE TABLE IF NOT EXISTS funds_schedules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            fs_date DATE NOT NULL,
            fs_desc TEXT NOT NULL,
            fs_total_recipients INT NOT NULL,
            fs_total_amount DECIMAL(14,2) NOT NULL,
            approved TINYINT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            deleted_at DATETIME NULL,
            INDEX funds_schedules_user_idx (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB
        """
    )

    execute(
        """
        CREATE TABLE IF NOT EXISTS fs_recipients (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            fs_id INT NOT NULL,
            recipient_id INT NOT NULL,
            fund_amount DECIMAL(14,2) NOT NULL,
            created_at DATETIME NOT NULL,
            deleted_at DATETIME NULL,
            INDEX fs_recipients_user_idx (user_id),
            INDEX fs_recipients_fs_id_idx (fs_id),
            INDEX fs_recipients_recipient_id_idx (recipient_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (fs_id) REFERENCES funds_schedules(id),
            FOREIGN KEY (recipient_id) REFERENCES funds_recipients(id)
        ) ENGINE=InnoDB
        """
    )

    if column_exists("airtime_schedules", "as_total_receipients") and not column_exists(
        "airtime_schedules", "as_total_recipients"
    ):
        execute(
            """
            ALTER TABLE airtime_schedules
            CHANGE COLUMN as_total_receipients as_total_recipients INT NOT NULL
            """
        )

    if column_exists("as_recipients", "receipient_id") and not column_exists(
        "as_recipients", "recipient_id"
    ):
        execute(
            """
            ALTER TABLE as_recipients
            CHANGE COLUMN receipient_id recipient_id INT NOT NULL
            """
        )

    execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            trans_type ENUM('in','out') NOT NULL,
            trans_amount DECIMAL(14,2) NOT NULL,
            platform_fee DECIMAL(14,2) NOT NULL DEFAULT 0.00,
            trans_ref VARCHAR(255) NOT NULL,
            trans_ref_type ENUM('airtime','funds','top-up') NOT NULL DEFAULT 'top-up',
            created_at DATETIME NOT NULL,
            INDEX transactions_user_idx (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB
        """
    )

    execute(
        """
        CREATE TABLE IF NOT EXISTS topup_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            transaction_id VARCHAR(64) NOT NULL,
            amount DECIMAL(14,2) NOT NULL,
            platform_fee DECIMAL(14,2) NOT NULL,
            method VARCHAR(40) NOT NULL,
            phone VARCHAR(20) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            UNIQUE KEY topup_requests_tx_idx (transaction_id),
            INDEX topup_requests_user_idx (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB
        """
    )

    trans_ref_type_column = select_one(
        """
        SELECT COLUMN_NAME
        FROM information_schema.columns
        WHERE table_schema = ? AND table_name = 'transactions' AND column_name = 'trans_ref_type'
        """,
        (MYSQL_DB,),
    )
    if trans_ref_type_column is None:
        execute(
            """
            ALTER TABLE transactions
            ADD COLUMN trans_ref_type ENUM('airtime','funds','top-up') NOT NULL DEFAULT 'top-up'
            AFTER trans_ref
            """
        )
        execute(
            """
            UPDATE transactions
            SET trans_ref_type = 'airtime'
            WHERE trans_type = 'out' AND trans_ref_type = 'top-up'
            """
        )

    platform_fee_column = select_one(
        """
        SELECT COLUMN_NAME
        FROM information_schema.columns
        WHERE table_schema = ? AND table_name = 'transactions' AND column_name = 'platform_fee'
        """,
        (MYSQL_DB,),
    )
    if platform_fee_column is None:
        execute(
            """
            ALTER TABLE transactions
            ADD COLUMN platform_fee DECIMAL(14,2) NOT NULL DEFAULT 0.00
            AFTER trans_amount
            """
        )

    execute(
        """
        CREATE TABLE IF NOT EXISTS wallet_balance (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            balance DECIMAL(14,2) NOT NULL DEFAULT 0.00,
            UNIQUE KEY wallet_balance_user_uidx (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB
        """
    )

    now = utc_now_str()
    admin = select_one("SELECT id FROM users WHERE email = ?", ("admin@bulkartime.local",))
    if admin is None:
        password_hash, password_salt = hash_password("admin123")
        execute(
            """
            INSERT INTO users
              (account_type, name, email, phone, password_hash, password_salt, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "business",
                "Admin",
                "admin@bulkartime.local",
                "+250700000000",
                password_hash,
                password_salt,
                now,
                now,
            ),
        )

    execute(
        """
        INSERT INTO wallet_balance (user_id, balance)
        SELECT u.id, 0.00
        FROM users u
        LEFT JOIN wallet_balance wb ON wb.user_id = u.id
        WHERE wb.id IS NULL
        """
    )

    execute(
        """
        UPDATE airtime_schedules
        SET approved = 0, updated_at = ?
        WHERE approved = 3 AND deleted_at IS NULL
        """,
        (utc_now_str(),),
    )

    execute("DELETE FROM sessions")


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "FarangaFloat/2.0"

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _send_json(self, status: int, payload: object, headers: dict | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(
        self, status: int, payload: str, content_type: str, headers: dict | None = None
    ) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, headers: dict | None = None) -> None:
        self.send_response(302)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.send_header("Location", location)
        self.end_headers()

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _read_form(self) -> tuple[dict, dict]:
        content_type = self.headers.get("Content-Type", "")
        if content_type.startswith("multipart/form-data"):
            boundary_token = None
            for part in content_type.split(";"):
                part = part.strip()
                if part.startswith("boundary="):
                    boundary_token = part.split("=", 1)[1]
                    break
            if not boundary_token:
                return {}, {}

            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            fields: dict[str, str] = {}
            files: dict[str, dict] = {}
            boundary = f"--{boundary_token}".encode("utf-8")
            parts = body.split(boundary)

            for part in parts:
                if not part or part in {b"--", b"--\r\n"}:
                    continue
                if part.startswith(b"\r\n"):
                    part = part[2:]
                if part.endswith(b"\r\n"):
                    part = part[:-2]
                if part.endswith(b"--"):
                    part = part[:-2]

                header_blob, _, content = part.partition(b"\r\n\r\n")
                if not header_blob:
                    continue

                headers = header_blob.decode("utf-8", errors="ignore").split("\r\n")
                disposition = next(
                    (h for h in headers if h.lower().startswith("content-disposition")),
                    "",
                )
                if not disposition:
                    continue

                name = None
                filename = None
                for item in disposition.split(";"):
                    item = item.strip()
                    if "=" in item:
                        key, value = item.split("=", 1)
                        value = value.strip().strip('"')
                        if key == "name":
                            name = value
                        if key == "filename":
                            filename = value
                if not name:
                    continue

                if filename:
                    files[name] = {"filename": filename, "content": content}
                else:
                    fields[name] = content.decode("utf-8", errors="ignore")

            return fields, files

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw)
        fields = {key: values[0] if values else "" for key, values in parsed.items()}
        return fields, {}

    def _save_upload(self, file_item: dict) -> str:
        filename = os.path.basename(file_item.get("filename") or "")
        ext = Path(filename).suffix if filename else ""
        safe_name = f"{secrets.token_hex(12)}{ext}"
        target = UPLOAD_DIR / safe_name
        with target.open("wb") as handle:
            handle.write(file_item.get("content", b""))
        return str(target.relative_to(ROOT))

    def _get_cookie(self, name: str) -> str | None:
        header = self.headers.get("Cookie")
        if not header:
            return None
        parts = header.split(";")
        for part in parts:
            if "=" in part:
                key, value = part.strip().split("=", 1)
                if key == name:
                    return value
        return None

    def _delete_session_by_id(self, session_id: str | None) -> None:
        if not session_id:
            return
        execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    def _create_session(self, user_id: int) -> str:
        session_id = secrets.token_hex(24)
        now = utc_now_str()
        if SESSION_TIMEOUT_DISABLED:
            expires_at = (utc_now() + timedelta(days=3650)).strftime("%Y-%m-%d %H:%M:%S")
        else:
            expires_at = (utc_now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
        execute(
            """
            INSERT INTO sessions (id, user_id, created_at, last_active_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, user_id, now, now, expires_at),
        )
        return session_id

    def _get_session_user(self, touch: bool = True) -> int | None:
        session_id = self._get_cookie(SESSION_COOKIE)
        if not session_id:
            return None

        row = select_one(
            "SELECT user_id, expires_at FROM sessions WHERE id = ?",
            (session_id,),
        )
        if row is None:
            return None

        user_id = int(row["user_id"])
        if SESSION_TIMEOUT_DISABLED:
            return user_id

        try:
            expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            self._delete_session_by_id(session_id)
            return None

        if expires_at < utc_now():
            self._delete_session_by_id(session_id)
            return None

        if touch:
            now = utc_now_str()
            new_expiry = (utc_now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
            execute(
                """
                UPDATE sessions
                SET last_active_at = ?, expires_at = ?
                WHERE id = ?
                """,
                (now, new_expiry, session_id),
            )
        return user_id

    def _require_user(self) -> int | None:
        try:
            user_id = self._get_session_user(touch=True)
        except MySQLError:
            self._send_json(500, {"error": "Database error."})
            return None

        if not user_id:
            self._send_json(401, {"error": "Unauthorized"})
            return None
        return user_id

    def _schedule_status(self, as_date_value: str, approved: int, deleted_at: str | None) -> str:
        if deleted_at or approved == 2:
            return "deleted"
        if approved == 1:
            return "executed"
        return "pending"

    def _schedule_flags(
        self, as_date_value: str, approved: int, deleted_at: str | None
    ) -> tuple[bool, bool, bool]:
        if deleted_at or approved == 2:
            return False, False, False

        can_edit = approved == 0
        can_approve = approved == 0
        can_delete = approved == 0
        return can_edit, can_approve, can_delete

    def _parse_id(self, value: str) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _ensure_wallet_row(self, user_id: int) -> None:
        execute(
            """
            INSERT INTO wallet_balance (user_id, balance)
            VALUES (?, 0.00)
            ON DUPLICATE KEY UPDATE user_id = user_id
            """,
            (user_id,),
        )

    def _get_wallet_balance_amount(self, user_id: int) -> Decimal:
        self._ensure_wallet_row(user_id)
        row = select_one("SELECT balance FROM wallet_balance WHERE user_id = ?", (user_id,))
        if row is None or row.get("balance") is None:
            return Decimal("0.00")
        return Decimal(str(row["balance"])).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    def _create_transaction(
        self,
        user_id: int,
        trans_type: str,
        amount: Decimal,
        trans_ref: str,
        platform_fee: Decimal = Decimal("0.00"),
        trans_ref_type: str = "top-up",
    ) -> tuple[int, Decimal]:
        normalized_amount = amount.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
        if normalized_amount <= 0:
            raise ValueError("Transaction amount must be greater than 0.")
        normalized_fee = platform_fee.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
        if normalized_fee < 0:
            raise ValueError("Platform fee cannot be negative.")

        self._ensure_wallet_row(user_id)
        now = utc_now_str()

        if trans_type == "in":
            execute(
                "UPDATE wallet_balance SET balance = balance + ? WHERE user_id = ?",
                (normalized_amount, user_id),
            )
        elif trans_type == "out":
            affected, _ = execute(
                """
                UPDATE wallet_balance
                SET balance = balance - ?
                WHERE user_id = ? AND balance >= ?
                """,
                (normalized_amount, user_id, normalized_amount),
            )
            if affected == 0:
                raise ValueError("Insufficient wallet balance.")
        else:
            raise ValueError("Invalid transaction type.")

        _, trans_id = execute(
            """
            INSERT INTO transactions
              (user_id, trans_type, trans_amount, platform_fee, trans_ref, trans_ref_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, trans_type, normalized_amount, normalized_fee, trans_ref, trans_ref_type, now),
        )
        balance = self._get_wallet_balance_amount(user_id)
        return trans_id, balance

    def _wallet_payload(self, user_id: int) -> dict:
        balance = self._get_wallet_balance_amount(user_id)
        tx_rows = select_all(
            """
            SELECT id, trans_type, trans_amount, platform_fee, trans_ref, trans_ref_type, created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 20
            """,
            (user_id,),
        )
        for row in tx_rows:
            row["id"] = int(row["id"])
            row["trans_amount"] = float(row["trans_amount"])
            row["platform_fee"] = float(row["platform_fee"])
        return {"balance": money_to_float(balance), "transactions": tx_rows}

    def _wallet_topup(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        try:
            amount = to_money(payload.get("amount"))
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            return

        phone = str(payload.get("phone") or "").strip()
        if not TOPUP_PHONE_REGEX.match(phone):
            self._send_json(400, {"error": "Phone number must start with 250 and contain 12 digits total."})
            return

        method = (payload.get("method") or "").strip()
        if method not in {"Mobile Money - MTN", "Mobile Money - Airtel"}:
            self._send_json(400, {"error": "Invalid top up method."})
            return

        user_row = select_one(
            """
            SELECT id, name, email, business_name, business_email
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        )
        if user_row is None:
            self._send_json(404, {"error": "User not found."})
            return

        payer_name = (
            user_row.get("business_name")
            or user_row.get("name")
            or user_row.get("email")
            or user_row.get("business_email")
            or "User"
        )
        payer_email = (user_row.get("business_email") or user_row.get("email") or "").strip()
        channel_name = "MOMO" if method == "Mobile Money - MTN" else "AIRTEL MONEY"
        platform_fee = (amount * Decimal("0.10")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
        total_charge = (amount + platform_fee).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

        gateway_payload = {
            "amount": str(total_charge),
            "channel_name": channel_name,
            "payer_code": str(user_id),
            "payer_names": str(payer_name).strip(),
            "phone_number": phone,
            "payer_email": payer_email,
        }

        try:
            request = Request(
                "https://bk-api.magiquetechnologies.tech/api/payment/initiate",
                data=json.dumps(gateway_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urlopen(request, timeout=20, context=ssl._create_unverified_context()) as response:
                response_body = response.read().decode("utf-8")
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="ignore")
            message = detail or "Unable to initiate payment."
            try:
                parsed = json.loads(detail)
                message = parsed.get("message") or parsed.get("error") or message
            except json.JSONDecodeError:
                pass
            self._send_json(int(getattr(error, "code", 502) or 502), {"error": message})
            return
        except URLError:
            self._send_json(502, {"error": "Unable to reach payment gateway."})
            return

        try:
            gateway_response = json.loads(response_body)
        except json.JSONDecodeError:
            self._send_json(502, {"error": "Invalid response from payment gateway."})
            return

        if not gateway_response.get("success"):
            message = (
                gateway_response.get("data", {}).get("message")
                or gateway_response.get("message")
                or "Payment initiation failed."
            )
            self._send_json(400, {"error": message})
            return

        internal_ref = (
            gateway_response.get("data", {})
            .get("data", {})
            .get("internal_transaction_ref_number")
        )
        if not internal_ref:
            self._send_json(502, {"error": "Payment gateway did not return a transaction reference."})
            return

        now = utc_now_str()
        execute(
            """
            INSERT INTO topup_requests
              (user_id, transaction_id, amount, platform_fee, method, phone, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            ON DUPLICATE KEY UPDATE
              amount = VALUES(amount),
              platform_fee = VALUES(platform_fee),
              method = VALUES(method),
              phone = VALUES(phone),
              status = 'pending',
              updated_at = VALUES(updated_at)
            """,
            (
                user_id,
                internal_ref,
                amount,
                platform_fee,
                method,
                phone,
                now,
                now,
            ),
        )

        message = gateway_response.get("data", {}).get("message") or "Transaction pending confirmation."
        self._send_json(
            200,
            {
                "status": "pending",
                "transaction_id": internal_ref,
                "message": message,
            },
        )

    def _wallet_topup_status(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        transaction_id = str(payload.get("transaction_id") or "").strip()
        if not transaction_id:
            self._send_json(400, {"error": "Missing transaction_id."})
            return

        request_row = select_one(
            """
            SELECT id, amount, platform_fee, status
            FROM topup_requests
            WHERE user_id = ? AND transaction_id = ?
            """,
            (user_id, transaction_id),
        )
        if request_row is None:
            self._send_json(404, {"error": "Transaction not found."})
            return

        status = str(request_row.get("status") or "pending").lower()
        if status == "success":
            self._send_json(200, {"status": "success", "message": "Transaction Successful"})
            return
        if status == "failed":
            self._send_json(200, {"status": "failed", "message": "Transaction Failed"})
            return

        try:
            request = Request(
                "https://bk-api.magiquetechnologies.tech/api/transaction/status",
                data=json.dumps({"transaction_id": transaction_id}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urlopen(request, timeout=20, context=ssl._create_unverified_context()) as response:
                response_body = response.read().decode("utf-8")
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="ignore")
            message = detail or "Unable to check transaction status."
            try:
                parsed = json.loads(detail)
                message = parsed.get("message") or parsed.get("error") or message
            except json.JSONDecodeError:
                pass
            self._send_json(int(getattr(error, "code", 502) or 502), {"error": message})
            return
        except URLError:
            self._send_json(502, {"error": "Unable to reach payment gateway."})
            return

        try:
            gateway_response = json.loads(response_body)
        except json.JSONDecodeError:
            self._send_json(502, {"error": "Invalid response from payment gateway."})
            return

        gateway_message = str(gateway_response.get("message") or "").strip()
        gateway_success = bool(gateway_response.get("success"))

        if gateway_success or "Successful" in gateway_message:
            existing = select_one(
                """
                SELECT id FROM transactions
                WHERE user_id = ? AND trans_ref = ? AND trans_ref_type = 'top-up'
                """,
                (user_id, transaction_id),
            )
            if existing is None:
                amount = Decimal(str(request_row.get("amount") or 0))
                platform_fee = Decimal(str(request_row.get("platform_fee") or 0))
                self._create_transaction(
                    user_id=user_id,
                    trans_type="in",
                    amount=amount,
                    trans_ref=transaction_id,
                    platform_fee=platform_fee,
                    trans_ref_type="top-up",
                )
            execute(
                """
                UPDATE topup_requests
                SET status = 'success', updated_at = ?
                WHERE id = ?
                """,
                (utc_now_str(), request_row["id"]),
            )
            self._send_json(200, {"status": "success", "message": gateway_message or "Transaction Successful"})
            return

        if "Pending" in gateway_message:
            self._send_json(200, {"status": "pending", "message": gateway_message or "Transaction Pending"})
            return

        if "Failed" in gateway_message:
            execute(
                """
                UPDATE topup_requests
                SET status = 'failed', updated_at = ?
                WHERE id = ?
                """,
                (utc_now_str(), request_row["id"]),
            )
            reason = str(gateway_response.get("reason") or "").strip()
            message = gateway_message or "Transaction Failed"
            if reason:
                message = f"{message}. {reason}"
            self._send_json(200, {"status": "failed", "message": message})
            return

        self._send_json(200, {"status": "pending", "message": gateway_message or "Transaction Pending"})

    def _get_wallet(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return
        self._send_json(200, self._wallet_payload(user_id))

    def _get_current_user(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        row = select_one(
            """
            SELECT id, account_type, name, email, phone, business_name, business_email
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        )
        if row is None:
            self._send_json(404, {"error": "User not found."})
            return

        account_type = str(row.get("account_type") or "individual")
        email = str(row.get("email") or row.get("business_email") or "").strip()
        if account_type == "business":
            display_name = str(row.get("business_name") or row.get("name") or email or "Business User")
        else:
            display_name = str(row.get("name") or email or "User")

        self._send_json(
            200,
            {
                "id": int(row["id"]),
                "account_type": account_type,
                "display_name": display_name.strip(),
                "email": email,
                "phone": (row.get("phone") or "").strip(),
            },
        )

    def _update_password(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        current_password = str(payload.get("current_password") or "")
        new_password = str(payload.get("new_password") or "")

        if not current_password or not new_password:
            self._send_json(400, {"error": "Current and new password are required."})
            return

        if len(new_password) < 6:
            self._send_json(400, {"error": "New password must be at least 6 characters."})
            return

        user_row = select_one(
            "SELECT password_hash, password_salt FROM users WHERE id = ?",
            (user_id,),
        )
        if user_row is None:
            self._send_json(404, {"error": "User not found."})
            return

        if not verify_password(
            current_password,
            str(user_row["password_hash"]),
            str(user_row["password_salt"]),
        ):
            self._send_json(400, {"error": "Current password is incorrect."})
            return

        password_hash, password_salt = hash_password(new_password)
        execute(
            """
            UPDATE users
            SET password_hash = ?, password_salt = ?, updated_at = ?
            WHERE id = ?
            """,
            (password_hash, password_salt, utc_now_str(), user_id),
        )
        self._send_json(200, {"status": "password_updated"})

    def _get_dashboard_data(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        now = today_local()
        year = now.year
        month_labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

        topups_rows = select_all(
            """
            SELECT MONTH(created_at) AS month_no, COALESCE(SUM(trans_amount), 0) AS total
            FROM transactions
            WHERE user_id = ? AND trans_type = 'in' AND trans_ref_type = 'top-up' AND YEAR(created_at) = ?
            GROUP BY MONTH(created_at)
            """,
            (user_id, year),
        )
        topups_by_month = {
            int(row["month_no"]): float(row["total"] or 0)
            for row in topups_rows
            if row.get("month_no") is not None
        }

        airtime_rows = select_all(
            """
            SELECT MONTH(created_at) AS month_no, COALESCE(SUM(trans_amount), 0) AS total
            FROM transactions
            WHERE user_id = ? AND trans_type = 'out' AND trans_ref_type = 'airtime' AND YEAR(created_at) = ?
            GROUP BY MONTH(created_at)
            """,
            (user_id, year),
        )
        airtime_by_month = {
            int(row["month_no"]): float(row["total"] or 0)
            for row in airtime_rows
            if row.get("month_no") is not None
        }

        funds_rows = select_all(
            """
            SELECT MONTH(created_at) AS month_no, COALESCE(SUM(trans_amount), 0) AS total
            FROM transactions
            WHERE user_id = ? AND trans_type = 'out' AND trans_ref_type = 'funds' AND YEAR(created_at) = ?
            GROUP BY MONTH(created_at)
            """,
            (user_id, year),
        )
        funds_by_month = {
            int(row["month_no"]): float(row["total"] or 0)
            for row in funds_rows
            if row.get("month_no") is not None
        }

        months = []
        for index, label in enumerate(month_labels, start=1):
            months.append(
                {
                    "month_no": index,
                    "label": label,
                    "topups": topups_by_month.get(index, 0.0),
                    "approved_airtime": airtime_by_month.get(index, 0.0),
                    "approved_funds": funds_by_month.get(index, 0.0),
                }
            )

        airtime_matrix_rows = select_all(
            """
            SELECT
              r.id AS recipient_id,
              r.name AS recipient_name,
              MONTH(t.created_at) AS month_no,
              COALESCE(SUM(ar.airtime_amount), 0) AS total
            FROM as_recipients ar
            JOIN airtime_schedules s ON s.id = ar.as_id AND s.user_id = ar.user_id
            JOIN recipients r ON r.id = ar.recipient_id AND r.user_id = ar.user_id
            JOIN transactions t ON t.user_id = s.user_id
              AND t.trans_type = 'out'
              AND t.trans_ref = CAST(s.id AS CHAR)
            WHERE ar.user_id = ?
              AND s.approved = 1
              AND s.deleted_at IS NULL
              AND ar.deleted_at IS NULL
              AND YEAR(t.created_at) = ?
            GROUP BY r.id, r.name, MONTH(t.created_at)
            ORDER BY r.name, month_no
            """,
            (user_id, year),
        )

        recipient_index: dict[int, dict] = {}
        for row in airtime_matrix_rows:
            recipient_id = int(row["recipient_id"])
            month_no = int(row["month_no"])
            total = float(row["total"] or 0)

            if recipient_id not in recipient_index:
                recipient_index[recipient_id] = {
                    "recipient_id": recipient_id,
                    "recipient_name": row.get("recipient_name") or "Unknown",
                    "monthly_totals": {},
                    "row_total": 0.0,
                }
            recipient_index[recipient_id]["monthly_totals"][str(month_no)] = total
            recipient_index[recipient_id]["row_total"] += total

        recipient_matrix = sorted(
            recipient_index.values(),
            key=lambda item: str(item["recipient_name"]).lower(),
        )

        funds_matrix_rows = select_all(
            """
            SELECT
              r.id AS recipient_id,
              r.name AS recipient_name,
              MONTH(t.created_at) AS month_no,
              COALESCE(SUM(fr.fund_amount), 0) AS total
            FROM fs_recipients fr
            JOIN funds_schedules s ON s.id = fr.fs_id AND s.user_id = fr.user_id
            JOIN funds_recipients r ON r.id = fr.recipient_id AND r.user_id = fr.user_id
            JOIN transactions t ON t.user_id = s.user_id
              AND t.trans_type = 'out'
              AND t.trans_ref_type = 'funds'
              AND t.trans_ref = CAST(s.id AS CHAR)
            WHERE fr.user_id = ?
              AND s.approved = 1
              AND s.deleted_at IS NULL
              AND fr.deleted_at IS NULL
              AND YEAR(t.created_at) = ?
            GROUP BY r.id, r.name, MONTH(t.created_at)
            ORDER BY r.name, month_no
            """,
            (user_id, year),
        )

        funds_index: dict[int, dict] = {}
        for row in funds_matrix_rows:
            recipient_id = int(row["recipient_id"])
            month_no = int(row["month_no"])
            total = float(row["total"] or 0)

            if recipient_id not in funds_index:
                funds_index[recipient_id] = {
                    "recipient_id": recipient_id,
                    "recipient_name": row.get("recipient_name") or "Unknown",
                    "monthly_totals": {},
                    "row_total": 0.0,
                }
            funds_index[recipient_id]["monthly_totals"][str(month_no)] = total
            funds_index[recipient_id]["row_total"] += total

        funds_matrix = sorted(
            funds_index.values(),
            key=lambda item: str(item["recipient_name"]).lower(),
        )

        self._send_json(
            200,
            {
                "year": year,
                "months": months,
                "airtime": {"recipient_matrix": recipient_matrix},
                "funds": {"recipient_matrix": funds_matrix},
            },
        )

    def _list_recipients(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        rows = select_all(
            """
            SELECT id, name, phone, carrier, created_at, updated_at
            FROM recipients
            WHERE user_id = ? AND deleted_at IS NULL
            ORDER BY created_at DESC
            """,
            (user_id,),
        )
        self._send_json(200, rows)

    def _create_recipient(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        name = (payload.get("name") or "").strip()
        phone = (payload.get("phone") or "").strip()
        carrier = (payload.get("carrier") or "").strip()

        if not name or not phone or not carrier:
            self._send_json(400, {"error": "Missing required fields."})
            return

        if not PHONE_REGEX.match(phone):
            self._send_json(400, {"error": "Phone must start with +250 and contain 9 digits."})
            return

        exists = select_one(
            """
            SELECT id FROM recipients
            WHERE user_id = ? AND phone = ? AND deleted_at IS NULL
            """,
            (user_id, phone),
        )
        if exists:
            self._send_json(409, {"error": "Phone number already exists."})
            return

        now = utc_now_str()
        _, recipient_id = execute(
            """
            INSERT INTO recipients (user_id, name, phone, carrier, created_at, updated_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL)
            """,
            (user_id, name, phone, carrier, now, now),
        )

        row = select_one(
            """
            SELECT id, name, phone, carrier, created_at, updated_at
            FROM recipients
            WHERE id = ? AND user_id = ?
            """,
            (recipient_id, user_id),
        )
        self._send_json(201, row or {})

    def _update_recipient(self, recipient_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        name = (payload.get("name") or "").strip()
        phone = (payload.get("phone") or "").strip()
        carrier = (payload.get("carrier") or "").strip()

        if not name or not phone or not carrier:
            self._send_json(400, {"error": "Missing required fields."})
            return

        if not PHONE_REGEX.match(phone):
            self._send_json(400, {"error": "Phone must start with +250 and contain 9 digits."})
            return

        exists = select_one(
            """
            SELECT id FROM recipients
            WHERE user_id = ? AND phone = ? AND deleted_at IS NULL AND id != ?
            """,
            (user_id, phone, recipient_id),
        )
        if exists:
            self._send_json(409, {"error": "Phone number already exists."})
            return

        affected, _ = execute(
            """
            UPDATE recipients
            SET name = ?, phone = ?, carrier = ?, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (name, phone, carrier, utc_now_str(), recipient_id, user_id),
        )
        if affected == 0:
            self._send_json(404, {"error": "Recipient not found."})
            return

        row = select_one(
            """
            SELECT id, name, phone, carrier, created_at, updated_at
            FROM recipients
            WHERE id = ? AND user_id = ?
            """,
            (recipient_id, user_id),
        )
        self._send_json(200, row or {})

    def _delete_recipient(self, recipient_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        affected, _ = execute(
            """
            UPDATE recipients
            SET deleted_at = ?, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (utc_now_str(), utc_now_str(), recipient_id, user_id),
        )
        if affected == 0:
            self._send_json(404, {"error": "Recipient not found."})
            return

        self._send_json(200, {"status": "deleted"})

    def _list_funds_recipients(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        rows = select_all(
            """
            SELECT id, name, phone, carrier, created_at, updated_at
            FROM funds_recipients
            WHERE user_id = ? AND deleted_at IS NULL
            ORDER BY created_at DESC
            """,
            (user_id,),
        )
        self._send_json(200, rows)

    def _create_funds_recipient(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        name = (payload.get("name") or "").strip()
        phone = (payload.get("phone") or "").strip()
        carrier = (payload.get("carrier") or "").strip()

        if not name or not phone or not carrier:
            self._send_json(400, {"error": "Missing required fields."})
            return

        if not PHONE_REGEX.match(phone):
            self._send_json(400, {"error": "Phone must start with +250 and contain 9 digits."})
            return

        exists = select_one(
            """
            SELECT id FROM funds_recipients
            WHERE user_id = ? AND phone = ? AND deleted_at IS NULL
            """,
            (user_id, phone),
        )
        if exists:
            self._send_json(409, {"error": "Phone number already exists."})
            return

        now = utc_now_str()
        _, recipient_id = execute(
            """
            INSERT INTO funds_recipients (user_id, name, phone, carrier, created_at, updated_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL)
            """,
            (user_id, name, phone, carrier, now, now),
        )

        row = select_one(
            """
            SELECT id, name, phone, carrier, created_at, updated_at
            FROM funds_recipients
            WHERE id = ? AND user_id = ?
            """,
            (recipient_id, user_id),
        )
        self._send_json(201, row or {})

    def _update_funds_recipient(self, recipient_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        name = (payload.get("name") or "").strip()
        phone = (payload.get("phone") or "").strip()
        carrier = (payload.get("carrier") or "").strip()

        if not name or not phone or not carrier:
            self._send_json(400, {"error": "Missing required fields."})
            return

        if not PHONE_REGEX.match(phone):
            self._send_json(400, {"error": "Phone must start with +250 and contain 9 digits."})
            return

        exists = select_one(
            """
            SELECT id FROM funds_recipients
            WHERE user_id = ? AND phone = ? AND deleted_at IS NULL AND id != ?
            """,
            (user_id, phone, recipient_id),
        )
        if exists:
            self._send_json(409, {"error": "Phone number already exists."})
            return

        affected, _ = execute(
            """
            UPDATE funds_recipients
            SET name = ?, phone = ?, carrier = ?, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (name, phone, carrier, utc_now_str(), recipient_id, user_id),
        )
        if affected == 0:
            self._send_json(404, {"error": "Recipient not found."})
            return

        row = select_one(
            """
            SELECT id, name, phone, carrier, created_at, updated_at
            FROM funds_recipients
            WHERE id = ? AND user_id = ?
            """,
            (recipient_id, user_id),
        )
        self._send_json(200, row or {})

    def _delete_funds_recipient(self, recipient_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        affected, _ = execute(
            """
            UPDATE funds_recipients
            SET deleted_at = ?, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (utc_now_str(), utc_now_str(), recipient_id, user_id),
        )
        if affected == 0:
            self._send_json(404, {"error": "Recipient not found."})
            return

        self._send_json(200, {"status": "deleted"})

    def _validate_schedule_payload(self, payload: dict) -> tuple[dict | None, str | None]:
        as_desc = (payload.get("as_desc") or "").strip()
        recipients = payload.get("recipients")

        if not as_desc:
            return None, "Schedule description is required."

        if not isinstance(recipients, list) or len(recipients) == 0:
            return None, "Select at least one recipient."

        normalized = []
        seen = set()
        total = Decimal("0.00")

        for item in recipients:
            try:
                recipient_id = int(item.get("recipient_id"))
            except (TypeError, ValueError):
                return None, "Invalid recipient selection."
            if recipient_id in seen:
                return None, "Recipients must be unique."
            seen.add(recipient_id)

            try:
                amount = to_money(item.get("airtime_amount"))
            except ValueError as error:
                message = str(error) or "Airtime amounts are invalid."
                return None, message

            normalized.append({"recipient_id": recipient_id, "airtime_amount": amount})
            total += amount

        return {
            "as_date": today_local().isoformat(),
            "as_desc": as_desc,
            "recipients": normalized,
            "as_total_recipients": len(normalized),
            "as_total_amount": total.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
        }, None

    def _recipient_count_for_user(self, user_id: int, recipient_ids: list[int]) -> int:
        placeholders = ",".join(["?"] * len(recipient_ids))
        query = (
            f"SELECT COUNT(*) AS total FROM recipients "
            f"WHERE user_id = ? AND deleted_at IS NULL AND id IN ({placeholders})"
        )
        row = select_one(query, (user_id, *recipient_ids))
        return int(row["total"]) if row and row.get("total") is not None else 0

    def _active_schedule_totals(self, user_id: int, schedule_id: int) -> tuple[int, Decimal]:
        row = select_one(
            """
            SELECT
              COUNT(ar.id) AS total_recipients,
              COALESCE(SUM(ar.airtime_amount), 0) AS total_amount
            FROM as_recipients ar
            JOIN recipients r ON r.id = ar.recipient_id AND r.user_id = ar.user_id
            WHERE ar.user_id = ?
              AND ar.as_id = ?
              AND ar.deleted_at IS NULL
              AND r.deleted_at IS NULL
            """,
            (user_id, schedule_id),
        )
        if row is None:
            return 0, Decimal("0.00")
        total_recipients = int(row.get("total_recipients") or 0)
        total_amount = Decimal(str(row.get("total_amount") or "0")).quantize(
            MONEY_QUANT, rounding=ROUND_HALF_UP
        )
        return total_recipients, total_amount

    def _update_schedule_totals(
        self, user_id: int, schedule_id: int, total_recipients: int, total_amount: Decimal
    ) -> None:
        execute(
            """
            UPDATE airtime_schedules
            SET as_total_recipients = ?, as_total_amount = ?, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (total_recipients, total_amount, utc_now_str(), schedule_id, user_id),
        )

    def _serialize_schedule(self, row: dict) -> dict:
        approved = int(row.get("approved") or 0)
        status = self._schedule_status(str(row.get("as_date")), approved, row.get("deleted_at"))
        can_edit, can_approve, can_delete = self._schedule_flags(
            str(row.get("as_date")), approved, row.get("deleted_at")
        )
        payload = dict(row)
        payload["approved"] = approved
        payload["as_total_recipients"] = int(payload.get("as_total_recipients") or 0)
        payload["as_total_amount"] = float(payload.get("as_total_amount") or 0)
        payload["status"] = status
        payload["can_edit"] = can_edit
        payload["can_approve"] = can_approve
        payload["can_delete"] = can_delete
        return payload

    def _list_schedules(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        rows = select_all(
            """
            SELECT id, as_date, as_desc, as_total_recipients, as_total_amount,
                   approved, created_at, updated_at, deleted_at
            FROM airtime_schedules
            WHERE user_id = ?
            ORDER BY as_date DESC, id DESC
            """,
            (user_id,),
        )
        self._send_json(200, [self._serialize_schedule(row) for row in rows])

    def _get_schedule(self, schedule_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        row = select_one(
            """
            SELECT id, as_date, as_desc, as_total_recipients, as_total_amount,
                   approved, created_at, updated_at, deleted_at
            FROM airtime_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        if row is None:
            self._send_json(404, {"error": "Schedule not found."})
            return

        recipients = select_all(
            """
            SELECT ar.id, ar.recipient_id, ar.airtime_amount, r.name, r.phone, r.carrier
            FROM as_recipients ar
            JOIN recipients r ON r.id = ar.recipient_id AND r.user_id = ar.user_id
            WHERE ar.user_id = ? AND ar.as_id = ? AND ar.deleted_at IS NULL
            ORDER BY r.name
            """,
            (user_id, schedule_id),
        )

        schedule_payload = self._serialize_schedule(row)
        for item in recipients:
            item["id"] = int(item["id"])
            item["recipient_id"] = int(item["recipient_id"])
            item["airtime_amount"] = float(item["airtime_amount"])
        schedule_payload["recipients"] = recipients
        self._send_json(200, schedule_payload)

    def _create_schedule(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        data, error = self._validate_schedule_payload(payload)
        if error:
            self._send_json(400, {"error": error})
            return

        recipient_ids = [item["recipient_id"] for item in data["recipients"]]
        if self._recipient_count_for_user(user_id, recipient_ids) != len(recipient_ids):
            self._send_json(400, {"error": "One or more recipients are invalid."})
            return

        wallet_balance = self._get_wallet_balance_amount(user_id)
        if data["as_total_amount"] > wallet_balance:
            self._send_json(
                400,
                {
                    "error": (
                        f"Insufficient wallet balance. "
                        f"Available: {money_to_float(wallet_balance)}"
                    )
                },
            )
            return

        now = utc_now_str()
        _, schedule_id = execute(
            """
            INSERT INTO airtime_schedules
              (user_id, as_date, as_desc, as_total_recipients, as_total_amount,
               approved, created_at, updated_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL)
            """,
            (
                user_id,
                data["as_date"],
                data["as_desc"],
                data["as_total_recipients"],
                data["as_total_amount"],
                now,
                now,
            ),
        )

        for item in data["recipients"]:
            execute(
                """
                INSERT INTO as_recipients
                  (user_id, as_id, recipient_id, airtime_amount, created_at, deleted_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (
                    user_id,
                    schedule_id,
                    item["recipient_id"],
                    item["airtime_amount"],
                    now,
                ),
            )

        row = select_one(
            """
            SELECT id, as_date, as_desc, as_total_recipients, as_total_amount,
                   approved, created_at, updated_at, deleted_at
            FROM airtime_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        self._send_json(201, self._serialize_schedule(row) if row else {})

    def _update_schedule(self, schedule_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        recipients = payload.get("recipients")
        if not isinstance(recipients, list) or len(recipients) == 0:
            self._send_json(400, {"error": "Recipients payload is required."})
            return

        schedule = select_one(
            """
            SELECT id, approved, deleted_at
            FROM airtime_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        if schedule is None:
            self._send_json(404, {"error": "Schedule not found."})
            return

        if int(schedule["approved"]) != 0 or schedule.get("deleted_at") is not None:
            self._send_json(403, {"error": "Only pending schedules can be edited."})
            return

        active_rows = select_all(
            """
            SELECT ar.recipient_id
            FROM as_recipients ar
            JOIN recipients r ON r.id = ar.recipient_id AND r.user_id = ar.user_id
            WHERE ar.user_id = ?
              AND ar.as_id = ?
              AND ar.deleted_at IS NULL
              AND r.deleted_at IS NULL
            """,
            (user_id, schedule_id),
        )
        active_ids = {int(row["recipient_id"]) for row in active_rows}
        if not active_ids:
            self._send_json(400, {"error": "Schedule has no active recipients."})
            return

        incoming_ids = set()
        amounts: dict[int, Decimal] = {}
        total_amount = Decimal("0.00")
        for item in recipients:
            try:
                recipient_id = int(item.get("recipient_id"))
            except (TypeError, ValueError):
                self._send_json(400, {"error": "Invalid recipient id in payload."})
                return

            if recipient_id in incoming_ids:
                self._send_json(400, {"error": "Duplicate recipient in payload."})
                return
            incoming_ids.add(recipient_id)

            try:
                amount = to_money(item.get("airtime_amount"))
            except ValueError as error:
                self._send_json(400, {"error": str(error)})
                return
            amounts[recipient_id] = amount
            total_amount += amount

        if incoming_ids != active_ids:
            self._send_json(
                400,
                {
                    "error": (
                        "You can only edit airtime amounts for recipients already in this schedule."
                    )
                },
            )
            return

        wallet_balance = self._get_wallet_balance_amount(user_id)
        if total_amount > wallet_balance:
            self._send_json(
                400,
                {
                    "error": (
                        f"Insufficient wallet balance. "
                        f"Available: {money_to_float(wallet_balance)}"
                    )
                },
            )
            return

        for recipient_id, amount in amounts.items():
            execute(
                """
                UPDATE as_recipients
                SET airtime_amount = ?
                WHERE user_id = ?
                  AND as_id = ?
                  AND recipient_id = ?
                  AND deleted_at IS NULL
                """,
                (amount, user_id, schedule_id, recipient_id),
            )

        self._update_schedule_totals(user_id, schedule_id, len(active_ids), total_amount)
        self._send_json(
            200,
            {
                "status": "updated",
                "as_total_recipients": len(active_ids),
                "as_total_amount": money_to_float(total_amount),
            },
        )

    def _delete_schedule(self, schedule_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        schedule = select_one(
            """
            SELECT id, approved, deleted_at
            FROM airtime_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        if schedule is None:
            self._send_json(404, {"error": "Schedule not found."})
            return

        if int(schedule["approved"]) != 0 or schedule.get("deleted_at") is not None:
            self._send_json(403, {"error": "Only pending schedules can be deleted."})
            return

        now = utc_now_str()
        execute(
            """
            UPDATE airtime_schedules
            SET approved = 2, deleted_at = ?, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (now, now, schedule_id, user_id),
        )
        execute(
            """
            UPDATE as_recipients
            SET deleted_at = ?
            WHERE as_id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (now, schedule_id, user_id),
        )
        self._send_json(200, {"status": "deleted"})

    def _approve_schedule(self, schedule_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        schedule = select_one(
            """
            SELECT id, as_date, approved, deleted_at
            FROM airtime_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        if schedule is None:
            self._send_json(404, {"error": "Schedule not found."})
            return

        if int(schedule["approved"]) != 0 or schedule.get("deleted_at") is not None:
            self._send_json(400, {"error": "Schedule is already approved or deleted."})
            return

        total_recipients, total_amount = self._active_schedule_totals(user_id, schedule_id)
        if total_recipients == 0 or total_amount <= 0:
            self._send_json(400, {"error": "Schedule has no active recipients to approve."})
            return

        wallet_balance = self._get_wallet_balance_amount(user_id)
        if total_amount > wallet_balance:
            self._send_json(
                400,
                {
                    "error": (
                        f"Insufficient wallet balance to approve this schedule. "
                        f"Available: {money_to_float(wallet_balance)}"
                    )
                },
            )
            return

        try:
            _, new_balance = self._create_transaction(
                user_id=user_id,
                trans_type="out",
                amount=total_amount,
                trans_ref=str(schedule_id),
                trans_ref_type="airtime",
            )
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            return

        self._update_schedule_totals(user_id, schedule_id, total_recipients, total_amount)
        execute(
            """
            UPDATE airtime_schedules
            SET approved = 1, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (utc_now_str(), schedule_id, user_id),
        )
        self._send_json(
            200,
            {
                "status": "approved",
                "debited_amount": money_to_float(total_amount),
                "balance": money_to_float(new_balance),
            },
        )

    def _validate_funds_schedule_payload(self, payload: dict) -> tuple[dict | None, str | None]:
        fs_desc = (payload.get("fs_desc") or "").strip()
        recipients = payload.get("recipients")

        if not fs_desc:
            return None, "Schedule description is required."

        if not isinstance(recipients, list) or len(recipients) == 0:
            return None, "Select at least one recipient."

        normalized = []
        seen = set()
        total = Decimal("0.00")

        for item in recipients:
            try:
                recipient_id = int(item.get("recipient_id"))
            except (TypeError, ValueError):
                return None, "Invalid recipient selection."
            if recipient_id in seen:
                return None, "Recipients must be unique."
            seen.add(recipient_id)

            try:
                amount = to_money(item.get("fund_amount"))
            except ValueError as error:
                return None, str(error) or "Fund amounts are invalid."

            normalized.append({"recipient_id": recipient_id, "fund_amount": amount})
            total += amount

        return {
            "fs_date": today_local().isoformat(),
            "fs_desc": fs_desc,
            "recipients": normalized,
            "fs_total_recipients": len(normalized),
            "fs_total_amount": total.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
        }, None

    def _funds_recipient_count_for_user(self, user_id: int, recipient_ids: list[int]) -> int:
        placeholders = ",".join(["?"] * len(recipient_ids))
        query = (
            f"SELECT COUNT(*) AS total FROM funds_recipients "
            f"WHERE user_id = ? AND deleted_at IS NULL AND id IN ({placeholders})"
        )
        row = select_one(query, (user_id, *recipient_ids))
        return int(row["total"]) if row and row.get("total") is not None else 0

    def _active_funds_schedule_totals(self, user_id: int, schedule_id: int) -> tuple[int, Decimal]:
        row = select_one(
            """
            SELECT
              COUNT(fr.id) AS total_recipients,
              COALESCE(SUM(fr.fund_amount), 0) AS total_amount
            FROM fs_recipients fr
            JOIN funds_recipients r ON r.id = fr.recipient_id AND r.user_id = fr.user_id
            WHERE fr.user_id = ?
              AND fr.fs_id = ?
              AND fr.deleted_at IS NULL
              AND r.deleted_at IS NULL
            """,
            (user_id, schedule_id),
        )
        if row is None:
            return 0, Decimal("0.00")
        total_recipients = int(row.get("total_recipients") or 0)
        total_amount = Decimal(str(row.get("total_amount") or "0")).quantize(
            MONEY_QUANT, rounding=ROUND_HALF_UP
        )
        return total_recipients, total_amount

    def _update_funds_schedule_totals(
        self, user_id: int, schedule_id: int, total_recipients: int, total_amount: Decimal
    ) -> None:
        execute(
            """
            UPDATE funds_schedules
            SET fs_total_recipients = ?, fs_total_amount = ?, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (total_recipients, total_amount, utc_now_str(), schedule_id, user_id),
        )

    def _serialize_funds_schedule(self, row: dict) -> dict:
        approved = int(row.get("approved") or 0)
        status = self._schedule_status(str(row.get("fs_date")), approved, row.get("deleted_at"))
        can_edit, can_approve, can_delete = self._schedule_flags(
            str(row.get("fs_date")), approved, row.get("deleted_at")
        )
        payload = dict(row)
        payload["approved"] = approved
        payload["fs_total_recipients"] = int(payload.get("fs_total_recipients") or 0)
        payload["fs_total_amount"] = float(payload.get("fs_total_amount") or 0)
        payload["status"] = status
        payload["can_edit"] = can_edit
        payload["can_approve"] = can_approve
        payload["can_delete"] = can_delete
        return payload

    def _list_funds_schedules(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        rows = select_all(
            """
            SELECT id, fs_date, fs_desc, fs_total_recipients, fs_total_amount,
                   approved, created_at, updated_at, deleted_at
            FROM funds_schedules
            WHERE user_id = ?
            ORDER BY fs_date DESC, id DESC
            """,
            (user_id,),
        )
        self._send_json(200, [self._serialize_funds_schedule(row) for row in rows])

    def _get_funds_schedule(self, schedule_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        row = select_one(
            """
            SELECT id, fs_date, fs_desc, fs_total_recipients, fs_total_amount,
                   approved, created_at, updated_at, deleted_at
            FROM funds_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        if row is None:
            self._send_json(404, {"error": "Schedule not found."})
            return

        recipients = select_all(
            """
            SELECT fr.id, fr.recipient_id, fr.fund_amount, r.name, r.phone, r.carrier
            FROM fs_recipients fr
            JOIN funds_recipients r ON r.id = fr.recipient_id AND r.user_id = fr.user_id
            WHERE fr.user_id = ? AND fr.fs_id = ? AND fr.deleted_at IS NULL
            ORDER BY r.name
            """,
            (user_id, schedule_id),
        )

        schedule_payload = self._serialize_funds_schedule(row)
        for item in recipients:
            item["id"] = int(item["id"])
            item["recipient_id"] = int(item["recipient_id"])
            item["fund_amount"] = float(item["fund_amount"])
        schedule_payload["recipients"] = recipients
        self._send_json(200, schedule_payload)

    def _create_funds_schedule(self) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        data, error = self._validate_funds_schedule_payload(payload)
        if error:
            self._send_json(400, {"error": error})
            return

        recipient_ids = [item["recipient_id"] for item in data["recipients"]]
        if self._funds_recipient_count_for_user(user_id, recipient_ids) != len(recipient_ids):
            self._send_json(400, {"error": "One or more recipients are invalid."})
            return

        wallet_balance = self._get_wallet_balance_amount(user_id)
        if data["fs_total_amount"] > wallet_balance:
            self._send_json(
                400,
                {
                    "error": (
                        f"Insufficient wallet balance. "
                        f"Available: {money_to_float(wallet_balance)}"
                    )
                },
            )
            return

        now = utc_now_str()
        _, schedule_id = execute(
            """
            INSERT INTO funds_schedules
              (user_id, fs_date, fs_desc, fs_total_recipients, fs_total_amount,
               approved, created_at, updated_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL)
            """,
            (
                user_id,
                data["fs_date"],
                data["fs_desc"],
                data["fs_total_recipients"],
                data["fs_total_amount"],
                now,
                now,
            ),
        )

        for item in data["recipients"]:
            execute(
                """
                INSERT INTO fs_recipients
                  (user_id, fs_id, recipient_id, fund_amount, created_at, deleted_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (
                    user_id,
                    schedule_id,
                    item["recipient_id"],
                    item["fund_amount"],
                    now,
                ),
            )

        row = select_one(
            """
            SELECT id, fs_date, fs_desc, fs_total_recipients, fs_total_amount,
                   approved, created_at, updated_at, deleted_at
            FROM funds_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        self._send_json(201, self._serialize_funds_schedule(row) if row else {})

    def _update_funds_schedule(self, schedule_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        recipients = payload.get("recipients")
        if not isinstance(recipients, list) or len(recipients) == 0:
            self._send_json(400, {"error": "Recipients payload is required."})
            return

        schedule = select_one(
            """
            SELECT id, approved, deleted_at
            FROM funds_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        if schedule is None:
            self._send_json(404, {"error": "Schedule not found."})
            return

        if int(schedule["approved"]) != 0 or schedule.get("deleted_at") is not None:
            self._send_json(403, {"error": "Only pending schedules can be edited."})
            return

        active_rows = select_all(
            """
            SELECT fr.recipient_id
            FROM fs_recipients fr
            JOIN funds_recipients r ON r.id = fr.recipient_id AND r.user_id = fr.user_id
            WHERE fr.user_id = ?
              AND fr.fs_id = ?
              AND fr.deleted_at IS NULL
              AND r.deleted_at IS NULL
            """,
            (user_id, schedule_id),
        )
        active_ids = {int(row["recipient_id"]) for row in active_rows}
        if not active_ids:
            self._send_json(400, {"error": "Schedule has no active recipients."})
            return

        incoming_ids = set()
        amounts: dict[int, Decimal] = {}
        total_amount = Decimal("0.00")
        for item in recipients:
            try:
                recipient_id = int(item.get("recipient_id"))
            except (TypeError, ValueError):
                self._send_json(400, {"error": "Invalid recipient id in payload."})
                return

            if recipient_id in incoming_ids:
                self._send_json(400, {"error": "Duplicate recipient in payload."})
                return
            incoming_ids.add(recipient_id)

            try:
                amount = to_money(item.get("fund_amount"))
            except ValueError as error:
                self._send_json(400, {"error": str(error)})
                return
            amounts[recipient_id] = amount
            total_amount += amount

        if incoming_ids != active_ids:
            self._send_json(
                400,
                {
                    "error": (
                        "You can only edit fund amounts for recipients already in this schedule."
                    )
                },
            )
            return

        wallet_balance = self._get_wallet_balance_amount(user_id)
        if total_amount > wallet_balance:
            self._send_json(
                400,
                {
                    "error": (
                        f"Insufficient wallet balance. "
                        f"Available: {money_to_float(wallet_balance)}"
                    )
                },
            )
            return

        for recipient_id, amount in amounts.items():
            execute(
                """
                UPDATE fs_recipients
                SET fund_amount = ?
                WHERE user_id = ?
                  AND fs_id = ?
                  AND recipient_id = ?
                  AND deleted_at IS NULL
                """,
                (amount, user_id, schedule_id, recipient_id),
            )

        self._update_funds_schedule_totals(user_id, schedule_id, len(active_ids), total_amount)
        self._send_json(
            200,
            {
                "status": "updated",
                "fs_total_recipients": len(active_ids),
                "fs_total_amount": money_to_float(total_amount),
            },
        )

    def _delete_funds_schedule(self, schedule_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        schedule = select_one(
            """
            SELECT id, approved, deleted_at
            FROM funds_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        if schedule is None:
            self._send_json(404, {"error": "Schedule not found."})
            return

        if int(schedule["approved"]) != 0 or schedule.get("deleted_at") is not None:
            self._send_json(403, {"error": "Only pending schedules can be deleted."})
            return

        now = utc_now_str()
        execute(
            """
            UPDATE funds_schedules
            SET approved = 2, deleted_at = ?, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (now, now, schedule_id, user_id),
        )
        execute(
            """
            UPDATE fs_recipients
            SET deleted_at = ?
            WHERE fs_id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (now, schedule_id, user_id),
        )
        self._send_json(200, {"status": "deleted"})

    def _approve_funds_schedule(self, schedule_id: int) -> None:
        user_id = self._require_user()
        if not user_id:
            return

        schedule = select_one(
            """
            SELECT id, fs_date, approved, deleted_at
            FROM funds_schedules
            WHERE id = ? AND user_id = ?
            """,
            (schedule_id, user_id),
        )
        if schedule is None:
            self._send_json(404, {"error": "Schedule not found."})
            return

        if int(schedule["approved"]) != 0 or schedule.get("deleted_at") is not None:
            self._send_json(400, {"error": "Schedule is already approved or deleted."})
            return

        total_recipients, total_amount = self._active_funds_schedule_totals(user_id, schedule_id)
        if total_recipients == 0 or total_amount <= 0:
            self._send_json(400, {"error": "Schedule has no active recipients to approve."})
            return

        wallet_balance = self._get_wallet_balance_amount(user_id)
        if total_amount > wallet_balance:
            self._send_json(
                400,
                {
                    "error": (
                        f"Insufficient wallet balance to approve this schedule. "
                        f"Available: {money_to_float(wallet_balance)}"
                    )
                },
            )
            return

        try:
            _, new_balance = self._create_transaction(
                user_id=user_id,
                trans_type="out",
                amount=total_amount,
                trans_ref=str(schedule_id),
                trans_ref_type="funds",
            )
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            return

        self._update_funds_schedule_totals(user_id, schedule_id, total_recipients, total_amount)
        execute(
            """
            UPDATE funds_schedules
            SET approved = 1, updated_at = ?
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            """,
            (utc_now_str(), schedule_id, user_id),
        )
        self._send_json(
            200,
            {
                "status": "approved",
                "debited_amount": money_to_float(total_amount),
                "balance": money_to_float(new_balance),
            },
        )

    def _handle_signup(self) -> None:
        fields, files = self._read_form()
        account_type = (fields.get("account_type") or "").strip()
        password = fields.get("password") or ""
        confirm_password = fields.get("confirm_password") or ""

        if password != confirm_password:
            self._redirect("signup.html?error=Passwords%20do%20not%20match")
            return
        if account_type not in {"individual", "business"}:
            self._redirect("signup.html?error=Select%20an%20account%20type")
            return

        now = utc_now_str()
        if account_type == "individual":
            name = (fields.get("name") or "").strip()
            email = (fields.get("email") or "").strip().lower()
            phone = (fields.get("phone") or "").strip()
            national_file = files.get("national_id")

            if not name or not email or not phone or national_file is None:
                self._redirect("signup.html?error=Missing%20required%20fields")
                return
            if not PHONE_REGEX.match(phone):
                self._redirect("signup.html?error=Invalid%20phone%20format")
                return

            national_id_path = self._save_upload(national_file)
            business_name = None
            business_email = None
            business_reg_no = None
            business_reg_path = None
        else:
            business_name = (fields.get("business_name") or "").strip()
            business_email = (fields.get("business_email") or "").strip().lower()
            business_reg_no = (fields.get("business_reg_no") or "").strip()
            business_file = files.get("business_registration")

            if not business_name or not business_email or not business_reg_no or business_file is None:
                self._redirect("signup.html?error=Missing%20required%20fields")
                return

            business_reg_path = self._save_upload(business_file)
            name = None
            email = business_email
            phone = None
            national_id_path = None

        password_hash, password_salt = hash_password(password)

        try:
            _, user_id = execute(
                """
                INSERT INTO users
                  (account_type, name, email, phone, national_id_path,
                   business_name, business_email, business_reg_no, business_reg_path,
                   password_hash, password_salt, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_type,
                    name,
                    email,
                    phone,
                    national_id_path,
                    business_name,
                    business_email,
                    business_reg_no,
                    business_reg_path,
                    password_hash,
                    password_salt,
                    now,
                    now,
                ),
            )
        except MySQLError as error:
            if "Duplicate entry" in str(error):
                self._redirect("signup.html?error=Email%20already%20exists")
                return
            self._redirect("signup.html?error=Unable%20to%20create%20account")
            return

        session_id = self._create_session(user_id)
        self._redirect(
            "index.html",
            headers={
                "Set-Cookie": f"{SESSION_COOKIE}={session_id}; HttpOnly; SameSite=Lax; Path=/"
            },
        )

    def _handle_login(self) -> None:
        fields, _ = self._read_form()
        email = (fields.get("email") or "").strip().lower()
        password = fields.get("password") or ""

        if not email or not password:
            self._redirect("login.html?error=Missing%20credentials")
            return

        user = select_one(
            "SELECT id, password_hash, password_salt FROM users WHERE email = ?",
            (email,),
        )
        if user is None or not verify_password(
            password, user["password_hash"], user["password_salt"]
        ):
            self._redirect("login.html?error=Invalid%20credentials")
            return

        session_id = self._create_session(int(user["id"]))
        self._redirect(
            "index.html",
            headers={
                "Set-Cookie": f"{SESSION_COOKIE}={session_id}; HttpOnly; SameSite=Lax; Path=/"
            },
        )

    def _handle_logout(self) -> None:
        session_id = self._get_cookie(SESSION_COOKIE)
        self._delete_session_by_id(session_id)
        self._send_json(
            200,
            {"status": "logged_out"},
            headers={"Set-Cookie": f"{SESSION_COOKIE}=deleted; Path=/; Max-Age=0"},
        )

    def _handle_api(self) -> bool:
        if not self.path.startswith("/api/"):
            return False

        path = self.path.split("?")[0]
        segments = [segment for segment in path.split("/") if segment]
        resource = segments[1] if len(segments) > 1 else ""

        try:
            if resource == "recipients":
                recipient_id = None
                if len(segments) == 3:
                    recipient_id = self._parse_id(segments[2])
                    if recipient_id is None:
                        self._send_json(400, {"error": "Invalid recipient id."})
                        return True

                if self.command == "GET" and len(segments) == 2:
                    self._list_recipients()
                    return True
                if self.command == "POST" and len(segments) == 2:
                    self._create_recipient()
                    return True
                if self.command == "PUT" and recipient_id is not None:
                    self._update_recipient(recipient_id)
                    return True
                if self.command == "DELETE" and recipient_id is not None:
                    self._delete_recipient(recipient_id)
                    return True

            if resource == "funds-recipients":
                recipient_id = None
                if len(segments) == 3:
                    recipient_id = self._parse_id(segments[2])
                    if recipient_id is None:
                        self._send_json(400, {"error": "Invalid recipient id."})
                        return True

                if self.command == "GET" and len(segments) == 2:
                    self._list_funds_recipients()
                    return True
                if self.command == "POST" and len(segments) == 2:
                    self._create_funds_recipient()
                    return True
                if self.command == "PUT" and recipient_id is not None:
                    self._update_funds_recipient(recipient_id)
                    return True
                if self.command == "DELETE" and recipient_id is not None:
                    self._delete_funds_recipient(recipient_id)
                    return True

            if resource == "schedules":
                schedule_id = None
                if len(segments) >= 3:
                    schedule_id = self._parse_id(segments[2])
                    if schedule_id is None:
                        self._send_json(400, {"error": "Invalid schedule id."})
                        return True

                if len(segments) == 4 and segments[3] == "approve" and self.command == "POST":
                    self._approve_schedule(schedule_id)
                    return True

                if self.command == "GET" and len(segments) == 2:
                    self._list_schedules()
                    return True
                if self.command == "GET" and len(segments) == 3 and schedule_id is not None:
                    self._get_schedule(schedule_id)
                    return True
                if self.command == "POST" and len(segments) == 2:
                    self._create_schedule()
                    return True
                if self.command == "PUT" and len(segments) == 3 and schedule_id is not None:
                    self._update_schedule(schedule_id)
                    return True
                if self.command == "DELETE" and len(segments) == 3 and schedule_id is not None:
                    self._delete_schedule(schedule_id)
                    return True

            if resource == "funds-schedules":
                schedule_id = None
                if len(segments) >= 3:
                    schedule_id = self._parse_id(segments[2])
                    if schedule_id is None:
                        self._send_json(400, {"error": "Invalid schedule id."})
                        return True

                if len(segments) == 4 and segments[3] == "approve" and self.command == "POST":
                    self._approve_funds_schedule(schedule_id)
                    return True

                if self.command == "GET" and len(segments) == 2:
                    self._list_funds_schedules()
                    return True
                if self.command == "GET" and len(segments) == 3 and schedule_id is not None:
                    self._get_funds_schedule(schedule_id)
                    return True
                if self.command == "POST" and len(segments) == 2:
                    self._create_funds_schedule()
                    return True
                if self.command == "PUT" and len(segments) == 3 and schedule_id is not None:
                    self._update_funds_schedule(schedule_id)
                    return True
                if self.command == "DELETE" and len(segments) == 3 and schedule_id is not None:
                    self._delete_funds_schedule(schedule_id)
                    return True

            if resource == "wallet":
                if self.command == "GET" and len(segments) == 2:
                    self._get_wallet()
                    return True
                if self.command == "POST" and len(segments) == 3 and segments[2] == "topup":
                    self._wallet_topup()
                    return True
                if (
                    self.command == "POST"
                    and len(segments) == 4
                    and segments[2] == "topup"
                    and segments[3] == "status"
                ):
                    self._wallet_topup_status()
                    return True

            if resource == "me":
                if self.command == "GET" and len(segments) == 2:
                    self._get_current_user()
                    return True
                if self.command == "PUT" and len(segments) == 3 and segments[2] == "password":
                    self._update_password()
                    return True

            if resource == "dashboard":
                if self.command == "GET" and len(segments) == 2:
                    self._get_dashboard_data()
                    return True

            self._send_json(405, {"error": "Method not allowed."})
            return True
        except MySQLError as error:
            self._send_json(500, {"error": f"Database error: {str(error)}"})
            return True

    def _serve_static(self) -> None:
        path = unquote(self.path.split("?")[0])
        if path == "/":
            path = "/index.html"

        public_pages = {"/login.html", "/signup.html"}
        protected_pages = {
            "/index.html",
            "/airtime-schedules.html",
            "/airtime-recipients.html",
            "/funds-schedules.html",
            "/funds-recipients.html",
            "/wallet.html",
            "/settings.html",
        }

        is_logged_in = self._get_session_user(touch=False) is not None

        if path in public_pages and is_logged_in:
            self._redirect("index.html")
            return

        if path in protected_pages and not is_logged_in:
            self._redirect("login.html")
            return

        if path.startswith("/data/") or path.endswith(".sqlite") or path.endswith("server.py"):
            self._send_text(404, "Not found", "text/plain; charset=utf-8")
            return

        requested = (ROOT / path.lstrip("/")).resolve()
        if not str(requested).startswith(str(ROOT)):
            self._send_text(404, "Not found", "text/plain; charset=utf-8")
            return

        if not requested.exists() or requested.is_dir():
            self._send_text(404, "Not found", "text/plain; charset=utf-8")
            return

        content_type, _ = mimetypes.guess_type(requested)
        content_type = content_type or "application/octet-stream"
        data = requested.read_bytes()

        self.send_response(200)
        if content_type.startswith("text/") or content_type in {
            "application/javascript",
            "application/json",
            "application/xml",
        }:
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        else:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self._handle_api():
            return
        self._serve_static()

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/signup":
            try:
                self._handle_signup()
            except MySQLError as error:
                self._redirect(f"signup.html?error={str(error)}")
            return
        if self.path == "/login":
            try:
                self._handle_login()
            except MySQLError as error:
                self._redirect(f"login.html?error={str(error)}")
            return
        if self.path == "/logout":
            self._handle_logout()
            return
        if self._handle_api():
            return
        self._send_json(404, {"error": "Not found."})

    def do_PUT(self) -> None:  # noqa: N802
        if self._handle_api():
            return
        self._send_json(404, {"error": "Not found."})

    def do_DELETE(self) -> None:  # noqa: N802
        if self._handle_api():
            return
        self._send_json(404, {"error": "Not found."})


def main() -> None:
    init_db()
    server = HTTPServer(("0.0.0.0", 8000), AdminHandler)
    print("Serving on http://localhost:8000")
    server.serve_forever()


if __name__ == "__main__":
    main()
