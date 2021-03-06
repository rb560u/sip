package vbmh

import (
	"fmt"
	airshipv1 "sipcluster/pkg/api/v1"
)

// ErrAuthTypeNotSupported is returned when wrong AuthType is provided
type ErrorConstraintNotFound struct {
}

func (e ErrorConstraintNotFound) Error() string {
	return "Invalid or Not found Schedulign Constraint"
}

type ErrorUnableToFullySchedule struct {
	TargetNode   airshipv1.VmRoles
	TargetFlavor string
}

func (e ErrorUnableToFullySchedule) Error() string {
	return fmt.Sprintf("Unable to complete a schedule with a target of  %v nodes, with a flavor of %v ", e.TargetNode, e.TargetFlavor)
}

type ErrorHostIpNotFound struct {
	HostName    string
	ServiceName airshipv1.InfraService
	IPInterface string
	Message     string
}

func (e ErrorHostIpNotFound) Error() string {
	return fmt.Sprintf("Unable to identify the vBMH Host %v IP address on interface %v required by Infrastructure Service %v %s ", e.HostName, e.IPInterface, e.ServiceName, e.Message)
}
