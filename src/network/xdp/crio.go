package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

type Labels struct {
	Name      string `json:"io.kubernetes.pod.name"`
	Namespace string `json:"io.kubernetes.pod.namespace"`
}

type Container struct {
	Labels       `json:"labels"`
	PodSandboxID string `json:"podSandboxId"`
}

type Result struct {
	Containers []Container `json:"containers"`
}

func (r *Result) NetworkInterfaces(namespace string) ([]*net.Interface, error) {
	if r == nil {
		return nil, fmt.Errorf("result is nil")
	}

	var interfaces []*net.Interface
	for _, container := range r.Containers {
		if container.Labels.Namespace != namespace {
			continue
		}
		name := container.PodSandboxID[0:15]
		iface, err := net.InterfaceByName(name)
		if err != nil {
			if strings.Contains(err.Error(), "no such network interface") {
				log.Printf("interface %q not found, skipping", name)
				continue
			} else {
				return nil, fmt.Errorf("lookup network interface %q: %s", name, err)
			}
		}
		log.Printf("interface %q found, adding", iface)
		interfaces = append(interfaces, iface)
	}
	return interfaces, nil
}

type ContainerRuntime struct{}

func NewContainerRuntime() *ContainerRuntime {
	return &ContainerRuntime{}
}

func (c *ContainerRuntime) PS() (*Result, error) {
	criCtlCmd := exec.Command("crictl", "ps", "-o", "json")
	outputJson, err := criCtlCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run crictl: %w", err)
	}

	var result Result
	if err := json.Unmarshal(outputJson, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	return &result, nil
}
