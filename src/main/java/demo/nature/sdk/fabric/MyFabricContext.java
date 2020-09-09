// Copyright (c) 2020 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0



package demo.nature.sdk.fabric;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.google.common.base.Strings;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.ChaincodeResponse.Status;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

/**
 * This class implements reading the configuration file (for Fabric connectivity)
 *   it also generates FabricClient and FabricCAClient instances based on these settings.
 *   for now, settings are hardcoded.
 * It also provides queryChaincode and invokeChaincode methods.
 *
 * The known bad side to this code is that it always works on a single endorsing peer.
 * Otherwise, it provides most necessary low-level boilerplate to start working with a Fabric network.
 *
 * This class also ensures that:
 *   - we have a valid user context (peer admin by default)
 *   - we have a channel that's created and initialized, with name defined by code (not ready configtx)
 *
 */
public final class MyFabricContext {

    private HFClient fabClient;
    private Channel fabChannel;
//    private String ccMetaId;
//    private String ccType;
//    private String ccMetaVersion;
    private String ccName;
    private TransactionRequest.Type ccMetaType;
    private FabricContextConfigYaml config;

    /**
     * This is the constructor of this Class
     * It coordinates the process of configuration of the network, channel and chaincode lifecycle - Hyperledger Fabric  v2.0
     *
     * @throws FabricContextException
     * @throws RuntimeException
     */
    public MyFabricContext() {

        // load config from file system
        try {
            String configPath = System.getProperty("fabricConfigFile", "./my-config-local.yaml");
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            mapper.findAndRegisterModules();
            config = mapper.readValue(new File(configPath), FabricContextConfigYaml.class);

        } catch (IOException e) {
            throw new FabricContextException(e);
        }

        try {
            fabClient = HFClient.createNewInstance();
            CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
            fabClient.setCryptoSuite(cryptoSuite);
            fabClient.setUserContext(getOrgAdmin(config.organizations.get(0)));

            ccName = config.channel.chaincode.name;
            String ccType = config.channel.chaincode.type;
//            ccMetaVersion = config.channel.chaincode.version;

            if (Strings.isNullOrEmpty(ccType) || ccType.compareToIgnoreCase("golang") == 0)
                ccMetaType = TransactionRequest.Type.GO_LANG;
            else if (ccType.compareToIgnoreCase("java") == 0)
                ccMetaType = TransactionRequest.Type.JAVA;
            else if (ccType.compareToIgnoreCase("node") == 0)
                ccMetaType = TransactionRequest.Type.NODE;
            else throw new FabricContextException(String.format("Invalid chaincode type '%s'", ccType));

            //Starts network configurations
            initNetworkConfiguration();

//            fabClient.setUserContext(getOrgAdmin(config.organizations.get(0)));

            //event listener
            addEventListerner();

        } catch (Throwable t) {
            if (RuntimeException.class.isAssignableFrom(t.getClass())) {
                throw (RuntimeException)t;
            } else {
                throw new FabricContextException(t);
            }
        }

    }

    private void addEventListerner() throws InvalidArgumentException {
        fabChannel.registerBlockListener(new BlockListener() {
            @Override
            public void received(BlockEvent blockEvent) {
                System.out.println("BlockListener : " + blockEvent.toString());
            }
        });

        fabChannel.registerChaincodeEventListener(Pattern.compile(".*"), Pattern.compile(Pattern.quote("initLedger")), new ChaincodeEventListener() {
            @Override
            public void received(String s, BlockEvent blockEvent, ChaincodeEvent chaincodeEvent) {
                System.out.println(String.format("ChaincodeEventListener %s %s %s", s, blockEvent.toString(), chaincodeEvent.toString() ));
            }
        });

        fabChannel.registerChaincodeEventListener(Pattern.compile(".*"), Pattern.compile(Pattern.quote("changeCarOwner")), new ChaincodeEventListener() {
            @Override
            public void received(String s, BlockEvent blockEvent, ChaincodeEvent chaincodeEvent) {
                System.out.println(String.format("ChaincodeEventListener %s %s %s", s, blockEvent.toString(), chaincodeEvent.toString() ));
            }
        });
    }


    /**
     * This method executes Hyperledger Fabric v2.0 network configuration
     *
     * @throws Exception
     */
    public void initNetworkConfiguration() throws Exception {
        Orderer connectedOrderer = null;
        Peer connectedPeer = null;

        for (FabricContextConfigYaml.OrganizationConfig org : config.organizations) {
            if(org.orderers != null) {
                for (FabricContextConfigYaml.NodeConfig orderer : org.orderers) {
                    connectedOrderer = createOrderer(orderer.url, orderer.name, org);
                    break;
                }
            }
        }

        for (FabricContextConfigYaml.OrganizationConfig org : config.organizations){
            if(org.peers != null) {
                for (FabricContextConfigYaml.NodeConfig configPeer : org.peers) {
                   connectedPeer = createPeer(configPeer.url, configPeer.name, org);
                   break;
                }
            }
        }


        //Construct and run the channel
        //TODO add logic to choose one from the list of orderers
        constructChannel(config.channel.name, connectedOrderer, connectedPeer);


        debugOut("That's all folks!");
    }


    private void constructChannel(String name, Orderer orderer, Peer peer) throws Exception {

        debugOut("Constructing channel %s", name);

        Channel channel = fabClient.newChannel(name);

        channel.addOrderer(orderer);
        debugOut("Created channel %s", name);


        channel.addPeer(peer);
        debugOut("Added peers to channel %s", channel.getName());


        channel.initialize();
        fabChannel = channel;
    }


    //Chaincode query methods
    public byte[] queryChaincode(String fcn) {
        return queryChaincode(fcn, new String[]{});
    }

    public byte[] queryChaincode(String fcn, String... args) {
        return queryChaincode(fcn, convertChaincodeArgs(args));
    }

    public byte[] queryChaincode(String fcn, byte[]... args) {

        try {

            long queryStart = System.currentTimeMillis();
            QueryByChaincodeRequest req = fabClient.newQueryProposalRequest();
            req.setChaincodeName(ccName);
            req.setFcn(fcn);
            req.setArgs(args);
            req.setProposalWaitTime(config.channel.chaincode.queryWaitTime);

            List<Peer> singlePeerList = new LinkedList<>();
            singlePeerList.add(fabChannel.getPeers().iterator().next());
            Collection<ProposalResponse> responses = fabChannel.queryByChaincode(req, singlePeerList);
            ProposalResponse rsp = responses.iterator().next();
            // check if status is not success
            if (rsp.getStatus() != Status.SUCCESS) {
                throw new FabricContextException(makeErrorFromProposalResponse(rsp));
            }
            byte[] result = rsp.getChaincodeActionResponsePayload();


            return result;

        } catch (Throwable t) {
            if (RuntimeException.class.isAssignableFrom(t.getClass())) {
                throw (RuntimeException)t;
            } else {
                throw new FabricContextException(t);
            }
        }

    }


    //Chaincode invoke methods
    public byte[]   invokeChaincode(String fcn) {
        return invokeChaincode(fcn, new String[]{});
    }

    public byte[] invokeChaincode(String fcn, String... args) {
        return invokeChaincode(fcn, convertChaincodeArgs(args));
    }

    public byte[] invokeChaincode(String fcn, byte[]... args) {
        String args_str = convertChaincodeArgsString(args);
        debugOut("args_str (%s)", args_str);


        final ExecutionException[] executionExceptions = new ExecutionException[1];

        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();

        TransactionProposalRequest transactionProposalRequest = fabClient.newTransactionProposalRequest();
        transactionProposalRequest.setChaincodeName(ccName);
        transactionProposalRequest.setChaincodeLanguage(ccMetaType);
        transactionProposalRequest.setUserContext(fabClient.getUserContext());
        if ("init".equals(fcn))
            transactionProposalRequest.setInit(true);

        debugOut("Invoke chaincode - going to call: %s on the chaincode %s", fcn, ccName);
        transactionProposalRequest.setFcn(fcn);
        transactionProposalRequest.setProposalWaitTime(config.channel.chaincode.invokeWaitTime);
        transactionProposalRequest.setArgs(args);

        long invokeStart = System.currentTimeMillis();
        byte[] result = null;

        Collection<ProposalResponse> transactionPropResp = null;

        try {
            transactionPropResp = fabChannel.sendTransactionProposal(transactionProposalRequest);

            for (ProposalResponse response : transactionPropResp) {
                if (response.getStatus() == Status.SUCCESS) {
                    //debugOut("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getURL());
                    successful.add(response);
                    if (result == null) {
                        result = response.getChaincodeActionResponsePayload();
                    } else {
                        byte[] localResult = response.getChaincodeActionResponsePayload();
                        if (!Arrays.equals(result, localResult)) {
                            throw new FabricContextException("Different peers returned different proposal response for Invoke");
                        }
                    }
                } else {
                    failed.add(response);
                }
            }

            debugOut("Received %d tx proposal responses. Successful+verified: %d . Failed: %d  - Fcn: %s ",
                    transactionPropResp.size(), successful.size(), failed.size(), fcn);

            if (failed.size() > 0) {
                ProposalResponse firstTransactionProposalResponse = failed.iterator().next();
                debugOut("Not enough endorsers for executeChaincode(move a,b,100):" + failed.size() + " endorser error: " +
                        firstTransactionProposalResponse.getMessage() +
                        ". Was verified: " + firstTransactionProposalResponse.isVerified());
            }

        } catch (ProposalException e) {
            e.printStackTrace();
        } catch (InvalidArgumentException e) {
            e.printStackTrace();
        }

        // all ok
        fabChannel.sendTransaction(successful).join();

        return result;

    }

    //Utilities gets
    public FabricContextConfigYaml getConfig() {
        return config;
    }


    public FabricUser getOrgAdmin(FabricContextConfigYaml.OrganizationConfig org) {
        String finalName = String.format("%s@%s", org.hlfClientUser, org.name);
        String skPath = String.format("%s/keystore", org.adminMsp);
        String certPath = String.format("%s/signcerts", org.adminMsp);

        return getLocalUser(finalName , skPath, certPath, org);
    }


    public HFClient getClient() {
        return fabClient;
    }
    private FabricUser getLocalUser( String finalName, String skPath, String certPath, FabricContextConfigYaml.OrganizationConfig org) {

        File skFile = null;
        File certFile = null;

        try {

            // find private key. in theory this can be found somehow... mathematically, but easier to just find it like this
            for (final File ent : new File(skPath).listFiles()) {
                if (!ent.isFile()) continue;
                if (ent.getName().endsWith("_sk")) {
                    skFile = ent;
                    break;
                }
            }

            certFile = new File(String.format("%s/%s-cert.pem", certPath, finalName));

        } catch (Throwable t) {
            if (RuntimeException.class.isAssignableFrom(t.getClass())) {
                throw (RuntimeException)t;
            } else {
                throw new RuntimeException(t);
            }
        }

        if (skFile == null || !skFile.exists() || !certFile.exists()) {
            if (skFile == null || !skFile.exists()) {
                throw new FabricContextException(String.format("%s private key does not exist at %s", finalName, (skFile==null)?"<null>":skFile.getAbsolutePath()));
            } else {
                throw new FabricContextException(String.format("%s signed certificate does not exist at %s", finalName, certFile.getAbsolutePath()));
            }
        }

        // do some debug logging
        debugOut("%s private key: %s", finalName, skFile.getAbsolutePath());
        debugOut("%s sign cert: %s", finalName, certFile.getAbsolutePath());

        // read in the cert
        String certPem = "";
        String skPem = "";
        try {

            skPem = new String(Files.readAllBytes(Paths.get(skFile.getAbsolutePath())), StandardCharsets.UTF_8);
            certPem = new String(Files.readAllBytes(Paths.get(certFile.getAbsolutePath())), StandardCharsets.UTF_8);

        } catch (Throwable t) {
            if (RuntimeException.class.isAssignableFrom(t.getClass())) {
                throw (RuntimeException)t;
            } else {
                throw new RuntimeException(t);
            }
        }

        // read in the private key.
        // tbh, in JS this is expressed with 2-3 lines...
        skPem = skPem.replace("-----BEGIN PRIVATE KEY-----\n", "");
        skPem = skPem.replace("-----END PRIVATE KEY-----\n", "");
        skPem = skPem.replaceAll("\\n", "");
        byte[] skEncoded = Base64.getDecoder().decode(skPem);
        PrivateKey skObject = null;
        try {

            KeyFactory kf = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec skSpec = new PKCS8EncodedKeySpec(skEncoded);
            skObject = kf.generatePrivate(skSpec);

        } catch (Throwable t) {
            if (RuntimeException.class.isAssignableFrom(t.getClass())) {
                throw (RuntimeException)t;
            } else {
                throw new RuntimeException(t);
            }
        }

        Enrollment e = new X509Enrollment(skObject, certPem);

        FabricUser u = new FabricUser(org.hlfClientUser, org.name, e, org.mspId);
        return u;

    }

    public Channel getChannel() {
        return fabChannel;
    }

    public void shutdown() {
        fabChannel.shutdown(true);
        fabChannel = null;
        fabClient = null;
    }

    private void debugOut(String fmt, Object param) {
        debugOut(fmt, new Object[]{param});
    }

    private void debugOut(String fmt, Object... params) {
        System.out.append(String.format(fmt+"%n", params));
        System.out.flush();
    }

    private Properties createProperties(double timeout, FabricContextConfigYaml.OrganizationConfig org, String domainOverride) {

        Properties props = new Properties();
        // read TLS cert file
        File cert = new File(org.hlfTlsCertFile);
        if (!cert.exists()) {
            throw new FabricContextException(String.format("TLS Certificate for \"%s\" not found or not readable (at %s)", domainOverride, org.hlfTlsCertFile));
        }
        File clientKey, clientCert = null;
        if(org.hlfClientAuth) {
            clientKey = new File(org.hlfClientKeyFile);
            if (!clientKey.exists()) {
                throw new FabricContextException(String.format("Client Key File for \"%s\" not found or not readable (at %s)", domainOverride, org.hlfClientKeyFile));
            }
            // @TODO try to change it to bytes
            props.setProperty("clientKeyFile", clientKey.getAbsolutePath());

            clientCert = new File(org.hlfClientCertFile);
            if (!clientCert.exists()) {
                throw new FabricContextException(String.format("Client Cert File for \"%s\" not found or not readable (at %s)", domainOverride, org.hlfClientCertFile));
            }
            // @TODO try to change it to bytes
            props.setProperty("clientCertFile", clientCert.getAbsolutePath());
        }

        // set cert property
        // @TODO try to change it to bytes
        props.setProperty("pemFile", cert.getAbsolutePath());
        props.setProperty("hostnameOverride", domainOverride);
        // not sure why is this needed:
        props.setProperty("sslProvider", "openSSL");
        props.setProperty("negotiationType", "TLS");
        // set timeout
        props.setProperty("ordererWaitTimeMilliSecs", String.format("%d", (int)(timeout * 1000)));
        props.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 1024*1024*100); // really large inbound message size

        return props;

    }

    /**
     * This method creates and instantiates Orderer object
     *
     * @param ordererURL orderer endpoint
     * @param ordererName orderer name
     * @param org organizationConfig of the orderer
     * @return Orderer object
     */
    private Orderer createOrderer(String ordererURL, String ordererName, FabricContextConfigYaml.OrganizationConfig org) {

        try {
            return fabClient.newOrderer(ordererName, ordererURL, createProperties(30, org, String.format("%s.%s", ordererName, org.name)));
        } catch (Throwable t) {
            if (RuntimeException.class.isAssignableFrom(t.getClass())) {
                throw (RuntimeException)t;
            } else {
                throw new FabricContextException(t);
            }
        }
    }

    /**
     * This method creates and instantiates Peer object
     *
     * @param peerURL peer endpoint
     * @param peerName peer name
     * @param org organizationConfig of the peer
     * @return Peer object
     */
    private Peer createPeer(String peerURL, String peerName, FabricContextConfigYaml.OrganizationConfig org) {

        try {
            return fabClient.newPeer(peerName, peerURL, createProperties(30, org, String.format("%s.%s", peerName,org.name)));
        } catch (Throwable t) {
            if (RuntimeException.class.isAssignableFrom(t.getClass())) {
                throw (RuntimeException)t;
            } else {
                throw new RuntimeException(t);
            }
        }

    }



    private String makeErrorFromProposalResponse(ProposalResponse rsp) {
        ProposalResponsePackage.ProposalResponse rsp2 = rsp.getProposalResponse();
        if (rsp2 != null) {
            return rsp2.toString();
        }

        int status = rsp.getStatus().getStatus();
        String message = rsp.getMessage();
        return String.format("Chaincode returned status %d (%s)", status, message);
    }

    private byte[][] convertChaincodeArgs(String[] args) {
        byte[][] byteArgs = new byte[args.length][];
        for (int i = 0; i < args.length; i++) {
            byteArgs[i] = args[i].getBytes(StandardCharsets.UTF_8);
        }
        return byteArgs;
    }

    private String convertChaincodeArgsString(byte[][] args) {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < args.length; i++) {
             String str = new String(args[i], StandardCharsets.UTF_8);
             buffer.append(str);
        }
        return buffer.toString();
    }
}
