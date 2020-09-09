// Copyright (c) 2020 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0



package demo.nature.sdk.fabric;

import java.util.List;

public class FabricContextConfigYaml {


    public static class OrganizationConfig {
        public String name;
        public String adminMsp;
        public String mspId;
        public List<NodeConfig> peers;
        public List<NodeConfig> orderers;
        public String hlfTlsCertFile;
        public String hlfClientKeyFile;
        public String hlfClientCertFile;
        public String hlfClientUser;
        public boolean hlfClientAuth;

        public OrganizationConfig() {}
    }

    // peer or orderer, or CA
    public static class NodeConfig {
        public String name;
        public String url;
        public NodeConfig() {}
    }

    // this is specifically for the demo client
    public static class ChannelConfig {
        public String name;
        public String channelTxFile;
        public String endorsementPolicy;
        public ChaincodeConfig chaincode;

        public ChannelConfig() {}
    }

    // chaincode info
    public static class ChaincodeConfig {
        public String name;
        public String gopath;
        public String version;
        public String metapath;
        public String entryPath;
        public String type;
        public Long queryWaitTime;
        public Long invokeWaitTime;


        public ChaincodeConfig() {}
    }

    // this is specifically for the demo client
    public static class ConnectorConfig {
        public int port;

        public ConnectorConfig() {}
    }

    public List<OrganizationConfig> organizations;
    public ConnectorConfig explorer;
    public ChannelConfig channel;
    public String ledgerId;
}
