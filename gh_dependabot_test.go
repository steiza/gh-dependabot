package main

import (
	"testing"
)

func TestSemverLess(t *testing.T) {
	if !semverLess("1.2.3", "4.5.6") {
		t.Error("1.2.3 should be less than 4.5.6")
	}

	if semverLess("4.5.6", "1.2.3") {
		t.Error("4.5.6 should not be less than 1.2.3")
	}

	if !semverLess("12.13.14", "12.13.15") {
		t.Error("12.13.14 should be less than 12.13.15")
	}

	if semverLess("12.13.15", "12.13.14") {
		t.Error("12.13.15 should not be less than 12.13.14")
	}
}
