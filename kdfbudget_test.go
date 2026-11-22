package zfscrypt

import (
	"errors"
	"strconv"
	"testing"

	"github.com/go-encryptions/kdfbudget"
)

// A dataset header is untrusted: pbkdf2iters = 1<<62 must be refused before
// any hashing (it used to loop for centuries).
func TestDeriveWrappingKeyRefusesHugeIters(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("1<<62 does not fit an int")
	}
	b := kdfbudget.Default()
	_, err := DeriveWrappingKeyBudget([]byte("p"), make([]byte, 8), 1<<62, b)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("got %v, want ErrLimit", err)
	}
	if b.Spent() != 0 {
		t.Errorf("a refusal spent %d units", b.Spent())
	}
	if _, err := DeriveWrappingKey([]byte("p"), make([]byte, 8), 1<<62); !errors.Is(err, ErrLimit) {
		t.Fatalf("DeriveWrappingKey: got %v, want ErrLimit", err)
	}
}

// OpenZFS's minimum (100000) and the largest count the default budget
// accepts (2^31) are within the budget; 2^31 is charged, not run.
func TestChargeItersAccepts(t *testing.T) {
	n := []int{100000}
	if strconv.IntSize == 64 {
		n = append(n, 1<<31)
	}
	for _, iters := range n {
		if err := chargeIters(kdfbudget.Default(), iters); err != nil {
			t.Errorf("iters %d refused: %v", iters, err)
		}
	}
	if _, err := DeriveWrappingKey([]byte("p"), make([]byte, 8), 100000); err != nil {
		t.Errorf("100000 iterations refused: %v", err)
	}
}

// A non-positive count is refused as such, not charged: a negative int would
// wrap to a huge uint64 and be reported as a budget overrun.
func TestChargeItersNonPositive(t *testing.T) {
	for _, iters := range []int{0, -1} {
		b := kdfbudget.Default()
		err := chargeIters(b, iters)
		if err == nil || errors.Is(err, ErrLimit) {
			t.Errorf("iters %d: got %v, want the positive-iters error", iters, err)
		}
		if b.Spent() != 0 {
			t.Errorf("iters %d spent %d units", iters, b.Spent())
		}
	}
}

func TestDeriveWrappingKeyBudgetNilRefuses(t *testing.T) {
	if _, err := DeriveWrappingKeyBudget([]byte("p"), make([]byte, 8), 1000, nil); err == nil {
		t.Fatal("a nil budget must refuse")
	}
}
