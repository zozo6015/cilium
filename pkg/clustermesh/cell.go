// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/metrics"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
)

type ClustermeshConfig struct {
	// AllowBuggyClustermesh determines whether to hard-fail startup due
	// to detection of a configuration combination that may trigger
	// connection impact in the dataplane due to clustermesh IDs
	// conflicting with other usage of skb->mark field. See GH-21330.
	AllowBuggyClustermesh bool
}

func (cfg ClustermeshConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("allow-buggy-clustermesh", false,
		"Allow the daemon to continue to operate even if conflicting clustermesh ID configuration is detected")
	flags.MarkHidden("allow-buggy-clustermesh")
}

var defaultConfig = ClustermeshConfig{
	AllowBuggyClustermesh: false,
}

var Cell = cell.Module(
	"clustermesh",
	"ClusterMesh is the Cilium multicluster implementation",

	cell.Provide(NewClusterMesh),

	// Convert concrete objects into more restricted interfaces used by clustermesh.
	cell.ProvidePrivate(func(sc *k8s.ServiceCache) ServiceMerger { return sc }),
	cell.ProvidePrivate(func(ipcache *ipcache.IPCache) ipcache.IPCacher { return ipcache }),
	cell.ProvidePrivate(func(mgr nodemanager.NodeManager) (nodeStore.NodeManager, kvstore.ClusterSizeDependantIntervalFunc) {
		return mgr, mgr.ClusterSizeDependantInterval
	}),
	cell.ProvidePrivate(idsMgrProvider),

	cell.Config(common.DefaultConfig),
	cell.Config(wait.TimeoutConfigDefault),
	cell.Config(defaultConfig),

	metrics.Metric(NewMetrics),
	metrics.Metric(common.MetricsProvider(subsystem)),

	cell.Invoke(func(info types.ClusterInfo, dcfg *option.DaemonConfig, cnimgr cni.CNIConfigManager, cfg Configuration) error {
		err := info.ValidateBuggyClusterID(dcfg.IPAM, cnimgr.GetChainingMode())
		if err != nil && cfg.ClustermeshConfig.AllowBuggyClustermesh {
			cfg.Logger.WithError(err).Error("Detected clustermesh ID configuration that may cause connection impact")
			return nil
		}
		return err
	}),
	cell.Invoke(ipsetNotifier),
	cell.Invoke(nodeManagerNotifier),
)
