UPDATE baseline_receipt
SET accepted=(SELECT COUNT(*) FROM baseline_member WHERE session_id=baseline_receipt.session_id);

CREATE TRIGGER baseline_member_count_insert
AFTER INSERT ON baseline_member
BEGIN
 UPDATE baseline_receipt SET accepted=accepted+1 WHERE session_id=NEW.session_id;
END;

CREATE TRIGGER baseline_member_no_update
BEFORE UPDATE ON baseline_member
BEGIN
 SELECT RAISE(ABORT, 'baseline membership is append-only');
END;

CREATE TRIGGER baseline_member_no_delete
BEFORE DELETE ON baseline_member
BEGIN
 SELECT RAISE(ABORT, 'baseline membership is append-only');
END;
