// Copyright (c) 2020 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0



package demo.nature.sdk.fabric;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.google.common.base.Strings;
import com.google.protobuf.InvalidProtocolBufferException;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.CompletableFuture;
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
public final class FabricContext {

    private HFClient fabClient;
    private Channel fabChannel;
    private String ccMetaId;
    private String ccType;
    private String ccMetaVersion;
    private String ccName;
    private TransactionRequest.Type ccMetaType;
    private FabricContextConfigYaml config;
    private boolean fabricTimeLogging = true;
    private HashMap<String, ArrayList<Peer>> peersByOrg;

    /**
     * This is the constructor of this Class
     * It coordinates the process of configuration of the network, channel and chaincode lifecycle - Hyperledger Fabric  v2.0
     *
     * @param doCreateChannel Is to create a channel
     * @throws FabricContextException
     * @throws RuntimeException
     */
    public FabricContext(boolean doCreateChannel) {

        // load config from file system
        try {
            String timingsProp = System.getProperty("fabricTimeLogging");
            fabricTimeLogging = (timingsProp != null);
            String configPath = System.getProperty("fabricConfigFile", "./config-local.yaml");
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            mapper.findAndRegisterModules();
            config = mapper.readValue(new File(configPath), FabricContextConfigYaml.class);

            peersByOrg = new HashMap<String, ArrayList<Peer>>();
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
            ccMetaVersion = config.channel.chaincode.version;

            if (Strings.isNullOrEmpty(ccType) || ccType.compareToIgnoreCase("golang") == 0)
                ccMetaType = TransactionRequest.Type.GO_LANG;
            else if (ccType.compareToIgnoreCase("java") == 0)
                ccMetaType = TransactionRequest.Type.JAVA;
            else if (ccType.compareToIgnoreCase("node") == 0)
                ccMetaType = TransactionRequest.Type.NODE;
            else throw new FabricContextException(String.format("Invalid chaincode type '%s'", ccType));

            //Starts network configurations
            initNetworkConfiguration(doCreateChannel);

            fabClient.setUserContext(getOrgAdmin(config.organizations.get(0)));

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
    public void initNetworkConfiguration(boolean createFabricChannel) throws Exception {

        ArrayList<Orderer> networkOrderers = new ArrayList<>();

        List<Peer> peers = new LinkedList<Peer>();
        Set<String> existingActiveChannels = new HashSet<String>();

        for (FabricContextConfigYaml.OrganizationConfig org : config.organizations) {
            if(org.orderers != null) {
                for (FabricContextConfigYaml.NodeConfig orderer : org.orderers) {
                    networkOrderers.add(createOrderer(orderer.url, orderer.name, org));
                }
            }
        }

        for (FabricContextConfigYaml.OrganizationConfig org : config.organizations){
            peersByOrg.put(org.name, new ArrayList<Peer>());
            if(org.peers != null) {
                for (FabricContextConfigYaml.NodeConfig configPeer : org.peers) {
                    Peer fabPeer = createPeer(configPeer.url, configPeer.name, org);
                    peers.add(fabPeer);
                    peersByOrg.get(org.name).add(fabPeer);
                    fabClient.setUserContext(getOrgAdmin(org));
                    existingActiveChannels.addAll(fabClient.queryChannels(fabPeer));
                }
            }
        }

        //Sanity check to see if channel already exists
        if (existingActiveChannels.contains(config.channel.name)) {
            createFabricChannel = false;
        }

        //Construct and run the channel
        //TODO add logic to choose one from the list of orderers
        constructChannel(config.channel.name, networkOrderers, peers, createFabricChannel);

        Path metaInfPath = null;
        if (Files.exists(Paths.get(config.channel.chaincode.metapath))) {
            metaInfPath = Paths.get(config.channel.chaincode.metapath);
            debugOut("META-INF folder detected. Starting chaincode with custom indexes");
        } else {
            debugOut("No META-INF folder detected. Starting chaincode without any custom indexes");
        }

        if (createFabricChannel) {
            LifecycleChaincodePackage lifecycleChaincodePackage = LifecycleChaincodePackage.fromSource(ccName, Paths.get(config.channel.chaincode.gopath), ccMetaType, config.channel.chaincode.entryPath, metaInfPath);
            runChannel(peers, lifecycleChaincodePackage);

            for(FabricContextConfigYaml.OrganizationConfig org : config.organizations) {
                for (Peer peer : peersByOrg.get(org.name)) {
                    fabClient.setUserContext(getOrgAdmin(org));
                    verifyNoInstalledChaincodes(Collections.singletonList(peer));
                }
            }
        }

        debugOut("That's all folks!");
    }

    /**
     * This method creates the channel in the network from a config file
     *
     * @param name Channel name
     * @param networkOrderers Orderer to be used in the new channel configuration
     * @param peers List of peers to add to the channel
     * @throws Exception
     */
    private void constructChannel(String name, List<Orderer> networkOrderers, List<Peer> peers, boolean createFabricChannel) throws Exception {

        debugOut("Constructing channel %s", name);

        ChannelConfiguration channelConfiguration;

        String txFile = config.channel.channelTxFile;

        if(txFile.isEmpty()){
          channelConfiguration = new ChannelConfiguration();
        }else{
          channelConfiguration = new ChannelConfiguration(new File(txFile));
        }
        Channel channel = createFabricChannel ? fabClient.newChannel(name, networkOrderers.get(0), channelConfiguration, fabClient.getChannelConfigurationSignature(channelConfiguration, getOrgAdmin(config.organizations.get(0)))) :
                fabClient.newChannel(name);

        for (Orderer orderer : networkOrderers) {
            channel.addOrderer(orderer);
        }
        debugOut("Created channel %s", name);

        if (createFabricChannel) {
            joinPeersToChannel(channel);
            debugOut("Joined peers to channel %s", channel.getName());
        } else {
            addPeersToChannel(channel);
            debugOut("Added peers to channel %s", channel.getName());
        }

        channel.initialize();
        fabChannel = channel;
    }

    /**
     * This method implements the chaincode lifecycle for the channel
     *
     * @param peers The peers that will have the chaincode installed
     * @param lifecycleChaincodePackage The available chaincode in test/fixture/chaincode
     */
    private void runChannel(Collection<Peer> peers, LifecycleChaincodePackage lifecycleChaincodePackage) {

        try {
            //Should be no chaincode installed at this time.
            debugOut("Orgs installs the chaincode on its peers.");

            long sequence = -1L;
            boolean firstPeer = true;
            int index = 0;
            LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy = LifecycleChaincodeEndorsementPolicy.fromSignaturePolicyYamlFile(Paths.get(config.channel.endorsementPolicy));

            for(FabricContextConfigYaml.OrganizationConfig org : config.organizations) {
                for (Peer peer : peersByOrg.get(org.name)) {

                    fabClient.setUserContext(getOrgAdmin(org));
                    String orgChaincodePackageID = lifecycleInstallChaincode(Collections.singletonList(peer), lifecycleChaincodePackage);

                    //Verifications to see if the chaincode is correctly installed
                    verifyByQueryInstalledChaincodes(getPeersOfMyOrg(peer), ccName, orgChaincodePackageID);
                    verifyByQueryInstalledChaincode(getPeersOfMyOrg(peer), orgChaincodePackageID);

                    if (firstPeer) {
                        firstPeer = false;
                        final QueryLifecycleQueryChaincodeDefinitionRequest queryLifecycleQueryChaincodeDefinitionRequest = fabClient.newQueryLifecycleQueryChaincodeDefinitionRequest();
                        queryLifecycleQueryChaincodeDefinitionRequest.setChaincodeName(ccName);

                        Collection<LifecycleQueryChaincodeDefinitionProposalResponse> firstQueryDefininitions = fabChannel.lifecycleQueryChaincodeDefinition(queryLifecycleQueryChaincodeDefinitionRequest, Collections.singletonList(peer));

                        for (LifecycleQueryChaincodeDefinitionProposalResponse firstDefinition : firstQueryDefininitions) {
                            if (firstDefinition.getStatus() == ProposalResponse.Status.SUCCESS) {
                                sequence = firstDefinition.getSequence() + 1L;
                                break;
                            } else {
                                if (404 == firstDefinition.getChaincodeActionResponseStatus()) {
                                    sequence = 1;
                                    break;
                                }
                            }
                        }
                    }

                    debugOut("Org going to approve chaincode definition for my org.");

                    CompletableFuture<BlockEvent.TransactionEvent> tx = lifecycleApproveChaincodeDefinitionForMyOrg(Collections.singleton(peer), "1",
                            chaincodeEndorsementPolicy, null, orgChaincodePackageID, sequence);
                    tx.join();

                    debugOut("Checking on org's network for approvals");

                    verifyByCheckCommitReadinessStatus(sequence, "1", chaincodeEndorsementPolicy, null, peers);
                }
            }

            debugOut("Org doing commit chaincode definition");

            CompletableFuture<BlockEvent.TransactionEvent> tx = commitChaincodeDefinitionRequest(sequence, "1", chaincodeEndorsementPolicy, null, peers);
            tx.join();

            //Init chaincode
            invokeChaincode("init");

        } catch (Exception e) {
            debugOut("Caught an exception running Channel %s", fabChannel.getName());
            e.printStackTrace();
        }
    }

    /**
     * This method installs the chaincode in peers
     *
     * @param peers the peers to have the chaincode installed
     * @param lifecycleChaincodePackage the chaincode package to be installed
     * @return PackageID of the installed chaincode
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    private String lifecycleInstallChaincode(Collection<Peer> peers, LifecycleChaincodePackage lifecycleChaincodePackage) throws InvalidArgumentException, ProposalException, InvalidProtocolBufferException {

        int numInstallProposal = 0;
        numInstallProposal = numInstallProposal + peers.size();
        LifecycleInstallChaincodeRequest installProposalRequest = fabClient.newLifecycleInstallChaincodeRequest();
        installProposalRequest.setLifecycleChaincodePackage(lifecycleChaincodePackage);
        installProposalRequest.setProposalWaitTime(config.channel.chaincode.invokeWaitTime);

        Collection<LifecycleInstallChaincodeProposalResponse> responses = fabClient.sendLifecycleInstallChaincodeRequest(installProposalRequest, peers);
        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();
        String packageID = null;

        for (LifecycleInstallChaincodeProposalResponse response : responses) {
            debugOut("message[%s]", response.getMessage());

            debugOut("Getting chaincode packageID status %s and packageID %s", response.getStatus(),response.getPackageId());
            if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                debugOut("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successful.add(response);
                packageID = response.getPackageId();
            } else {
                failed.add(response);
            }
        }

        debugOut("Received %d install proposal responses. Successful+verified: %d . Failed: %d", numInstallProposal, successful.size(), failed.size());

        if (failed.size() > 0) {
            ProposalResponse first = failed.iterator().next();
            debugOut("Received a failed proposal: status %s", first.getChaincodeActionResponseStatus());
        }

        return packageID;

    }

    /**
     * This method approves the chaincode definition for a given organization
     *
     * @param peers the peers to have the chaincode approved
     * @param chaincodeVersion chaincode version
     * @param chaincodeEndorsementPolicy chaincode endorsement policy
     * @param chaincodeCollectionConfiguration chaincode collection configuration
     * @param orgChaincodePackageID chaincode packageID of the org
     * @param sequence sequence number
     * @return CompletableFuture<BlockEvent.TransactionEvent> with the transaction result
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    private CompletableFuture<BlockEvent.TransactionEvent> lifecycleApproveChaincodeDefinitionForMyOrg(Collection<Peer> peers, String chaincodeVersion,
                                                                                                       LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                                                                                       ChaincodeCollectionConfiguration chaincodeCollectionConfiguration,
                                                                                                       String orgChaincodePackageID, Long sequence) throws InvalidArgumentException, ProposalException {

        LifecycleApproveChaincodeDefinitionForMyOrgRequest lifecycleApproveChaincodeDefinitionForMyOrgRequest = fabClient.newLifecycleApproveChaincodeDefinitionForMyOrgRequest();
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setSequence(sequence);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeName(ccName);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeVersion(chaincodeVersion);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setInitRequired(true);

        if (null != chaincodeCollectionConfiguration) {
            lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }

        if (null != chaincodeEndorsementPolicy) {
            lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }

        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setPackageId(orgChaincodePackageID);
        Collection<LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse> lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse =
                fabChannel.sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(lifecycleApproveChaincodeDefinitionForMyOrgRequest, peers);

       for (LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse response : lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse) {
            final Peer peer = response.getPeer();
                debugOut("lifecycleApproveChaincodeDefinitionForMyOrg: Peer %s status %s verified %s", peer.getUrl(), response.getStatus(), response.isVerified());
        }
        return fabChannel.sendTransaction(lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse);

    }

    /**
     * This method commits the chaincode definition for a given organization
     *
     * @param definitionSequence sequence number
     * @param chaincodeVersion chaincode version
     * @param chaincodeEndorsementPolicy chaincode endorsement policy
     * @param chaincodeCollectionConfiguration chaincode collection configuration
     * @param endorsingPeers peers that will commit the chaincode definition
     * @return CompletableFuture<BlockEvent.TransactionEvent>
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    private CompletableFuture<BlockEvent.TransactionEvent> commitChaincodeDefinitionRequest(long definitionSequence, String chaincodeVersion,
                                                                                            LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                                                                            ChaincodeCollectionConfiguration chaincodeCollectionConfiguration,
                                                                                            Collection<Peer> endorsingPeers) throws ProposalException, InvalidArgumentException {

        LifecycleCommitChaincodeDefinitionRequest lifecycleCommitChaincodeDefinitionRequest = fabClient.newLifecycleCommitChaincodeDefinitionRequest();
        lifecycleCommitChaincodeDefinitionRequest.setSequence(definitionSequence);
        lifecycleCommitChaincodeDefinitionRequest.setChaincodeName(ccName);
        lifecycleCommitChaincodeDefinitionRequest.setChaincodeVersion(chaincodeVersion);
        if (null != chaincodeEndorsementPolicy) {
            lifecycleCommitChaincodeDefinitionRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }
        if (null != chaincodeCollectionConfiguration) {
            lifecycleCommitChaincodeDefinitionRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }
        lifecycleCommitChaincodeDefinitionRequest.setInitRequired(true);

        Collection<LifecycleCommitChaincodeDefinitionProposalResponse> lifecycleCommitChaincodeDefinitionProposalResponses = fabChannel.sendLifecycleCommitChaincodeDefinitionProposal(lifecycleCommitChaincodeDefinitionRequest,
                endorsingPeers);

        for (LifecycleCommitChaincodeDefinitionProposalResponse resp : lifecycleCommitChaincodeDefinitionProposalResponses) {
            final Peer peer = resp.getPeer();
            debugOut("commitChaincodeDefinitionRequest response: Peer %s Status %s Verified %s", peer.getUrl(),resp.getStatus(), resp.isVerified());
        }

        return fabChannel.sendTransaction(lifecycleCommitChaincodeDefinitionProposalResponses);

    }

    /**
     * This method is used to verify and simulate the chaincode definition commit
     *
     * @param definitionSequence sequence number
     * @param chaincodeVersion chaincode version
     * @param chaincodeEndorsementPolicy chaincode endorsement policy
     * @param chaincodeCollectionConfiguration chaincode collection configuration
     * @param endorsingPeers peers that have the commit readiness verified
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    private void verifyByCheckCommitReadinessStatus(long definitionSequence, String chaincodeVersion, LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                                    ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, Collection<Peer> endorsingPeers) throws InvalidArgumentException, ProposalException {

        LifecycleCheckCommitReadinessRequest lifecycleCheckCommitReadinessRequest = fabClient.newLifecycleSimulateCommitChaincodeDefinitionRequest();
        lifecycleCheckCommitReadinessRequest.setSequence(definitionSequence);
        lifecycleCheckCommitReadinessRequest.setChaincodeName(ccName);
        lifecycleCheckCommitReadinessRequest.setChaincodeVersion(chaincodeVersion);
        if (null != chaincodeEndorsementPolicy) {
            lifecycleCheckCommitReadinessRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }
        if (null != chaincodeCollectionConfiguration) {
            lifecycleCheckCommitReadinessRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }
        lifecycleCheckCommitReadinessRequest.setInitRequired(true);

        Collection<LifecycleCheckCommitReadinessProposalResponse> lifecycleSimulateCommitChaincodeDefinitionProposalResponse = fabChannel.sendLifecycleCheckCommitReadinessRequest(lifecycleCheckCommitReadinessRequest, endorsingPeers);

        for (LifecycleCheckCommitReadinessProposalResponse resp : lifecycleSimulateCommitChaincodeDefinitionProposalResponse) {
            final Peer peer = resp.getPeer();
            debugOut("verifyByCheckCommitReadinessStatus Peer %s Status %s Approved Orgs [%s] UnApproved Orgs [%s]",
                    peer.getUrl(), resp.getStatus(), resp.getApprovedOrgs(), resp.getUnApprovedOrgs());
        }

    }

    /**
     * Verification that there are no installed chaincodes
     *
     * @param peers the peers to be verified
     * @return boolean
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    private boolean verifyNoInstalledChaincodes(Collection<Peer> peers) throws ProposalException, InvalidArgumentException {

        Collection<LifecycleQueryInstalledChaincodesProposalResponse> results = fabClient.sendLifecycleQueryInstalledChaincodes(fabClient.newLifecycleQueryInstalledChaincodesRequest(), peers);
        if (null == results || peers.size() != results.size()) {
            return false;
        }

        for (LifecycleQueryInstalledChaincodesProposalResponse result : results) {
            final String peerName = result.getPeer().getName();

            if (null == peerName)
                return false;

            if (!Status.SUCCESS.equals(result.getStatus())) {
                return false;
            }

            Collection<LifecycleQueryInstalledChaincodesProposalResponse.LifecycleQueryInstalledChaincodesResult> lifecycleQueryInstalledChaincodesResult = result.getLifecycleQueryInstalledChaincodesResult();
            if (!lifecycleQueryInstalledChaincodesResult.isEmpty()) {
                return false;
            }
        }

        return true;

    }

    /**
     * Verify if the chaincode installed has the expected label and packageID
     *
     * @param peers The peers to check if the DAML on fabric chaincode was installed correctly
     * @param expectedChaincodeLabel The expected label to be checked
     * @param expectedPackageId The expected DAML on fabric chaincode packageID to be checked
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    private void verifyByQueryInstalledChaincodes(Collection<Peer> peers, String expectedChaincodeLabel, String expectedPackageId) throws ProposalException, InvalidArgumentException {

        Collection<LifecycleQueryInstalledChaincodesProposalResponse> results = fabClient.sendLifecycleQueryInstalledChaincodes(fabClient.newLifecycleQueryInstalledChaincodesRequest(), peers);

        for (LifecycleQueryInstalledChaincodesProposalResponse peerResults : results) {
            final String peerName = peerResults.getPeer().getName();
            if ( !ChaincodeResponse.Status.SUCCESS.equals(peerResults.getStatus() )) {
                debugOut("Something went bad with verifyByQueryInstalledChaincodes");
            }

            for (LifecycleQueryInstalledChaincodesProposalResponse.LifecycleQueryInstalledChaincodesResult lifecycleQueryInstalledChaincodesResult : peerResults.getLifecycleQueryInstalledChaincodesResult()) {
                if (expectedPackageId.equals(lifecycleQueryInstalledChaincodesResult.getPackageId())) {
                    if ( !expectedChaincodeLabel.equals(lifecycleQueryInstalledChaincodesResult.getLabel())){
                        debugOut("Peer " + peerName + " had chaincode label mismatch");
                    }
                    break;
                }
            }
        }

    }

    /**
     * This will verify if the chaincode is installed correctly
     *
     * @param peers The peers to check if the DAML on fabric chaincode was installed correctly
     * @param packageId The chaincode packageID
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    private void verifyByQueryInstalledChaincode(Collection<Peer> peers, String packageId) throws ProposalException, InvalidArgumentException {

        final LifecycleQueryInstalledChaincodeRequest lifecycleQueryInstalledChaincodeRequest = fabClient.newLifecycleQueryInstalledChaincodeRequest();
        if (packageId == null){
            debugOut("CAREFUL The packageID has returned null");
            return;
        }
        lifecycleQueryInstalledChaincodeRequest.setPackageID(packageId);

        Collection<LifecycleQueryInstalledChaincodeProposalResponse> responses = fabClient.sendLifecycleQueryInstalledChaincode(lifecycleQueryInstalledChaincodeRequest, peers);

        for (LifecycleQueryInstalledChaincodeProposalResponse response : responses) {
            String peerName = response.getPeer().getName();
            debugOut("verifyByQueryInstalledChaincode: Peer %s with status %s , label %s", peerName, response.getStatus(), response.getLabel());
        }
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

            if (fabricTimeLogging)
                debugOut("queryChaincode (%s) - %dms %n", fcn, System.currentTimeMillis()-queryStart);

            return result;

        } catch (Throwable t) {
            if (RuntimeException.class.isAssignableFrom(t.getClass())) {
                throw (RuntimeException)t;
            } else {
                throw new FabricContextException(t);
            }
        }

    }

    public byte[] querySystemChaincode(String cc, String fcn, String... args) {

        try {

            QueryByChaincodeRequest req = fabClient.newQueryProposalRequest();
            req.setChaincodeName(cc);
            req.setFcn(fcn);
            req.setArgs(args);
            Collection<ProposalResponse> responses = fabChannel.queryByChaincode(req);
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
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
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
        if (fabricTimeLogging)
            debugOut("invokeChaincode (%s) - %dms %n", fcn, System.currentTimeMillis()-invokeStart);

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

    /**
     * Joins peers to a Channel
     *
     * @param channel Channel to have the peers joined
     * @throws Exception
     */
    private void joinPeersToChannel (Channel channel) throws Exception {

        for (FabricContextConfigYaml.OrganizationConfig o : config.organizations) {
            for (Peer peer : peersByOrg.get(o.name)) {
                fabClient.setUserContext(getOrgAdmin(o));
                channel.joinPeer(peer);
                debugOut("Peer %s %s joined channel %s", peer.getName(), peer.getUrl(), channel.getName());
            }
        }
    }

    /**
     * Adds peers that have joined previously to the existing Channel
     *
     * @param channel Channel to have the peers addded
     * @throws Exception
     */
    private void addPeersToChannel (Channel channel) throws Exception {

        for (FabricContextConfigYaml.OrganizationConfig o : config.organizations) {
            for (Peer peer : peersByOrg.get(o.name)) {
                fabClient.setUserContext(getOrgAdmin(o));
                channel.addPeer(peer);
                debugOut("Peer %s %s joined channel %s", peer.getName(), peer.getUrl(), channel.getName());
            }
        }

    }

    private ArrayList<Peer> getPeersOfMyOrg (Peer peer) {
        for ( String org : peersByOrg.keySet() ) {
            ArrayList<Peer> peersOfOrg = peersByOrg.get(org);
            if (peersOfOrg.contains(peer)) {
                return peersOfOrg;
            }
        }
        return null;
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
