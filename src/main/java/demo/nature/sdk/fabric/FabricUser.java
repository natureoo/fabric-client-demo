// Copyright (c) 2020 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0



package demo.nature.sdk.fabric;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;

import java.util.Set;

// FabricUser represents a User record with some predefined properties.
public class FabricUser implements User {

    private final String userName; // Admin
    private final String userAffiliation; // org1.example.com
    private final Enrollment userEnrollment; //
    private final String userMspID; // Org1MSP
    
    public FabricUser(String name, String affiliation, Enrollment enrollment, String mspid) {
        
        userName = name;
        userAffiliation = affiliation;
        userEnrollment = enrollment;
        userMspID = mspid;
        
    }
    
    public String getName() {
        return userName;
    }

    public Set<String> getRoles() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public String getAccount() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public String getAffiliation() {
        return userAffiliation;
    }

    public Enrollment getEnrollment() {
        return userEnrollment;
    }

    public String getMspId() {
        return userMspID;
    }

}

