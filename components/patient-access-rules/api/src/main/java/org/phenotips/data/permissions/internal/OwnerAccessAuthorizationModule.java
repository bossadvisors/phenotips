/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */
package org.phenotips.data.permissions.internal;

import org.phenotips.groups.GroupManager;
import org.phenotips.security.authorization.AuthorizationModule;

import org.phenotips.data.Patient;
import org.phenotips.data.PatientRepository;
import org.phenotips.data.permissions.PatientAccess;
import org.phenotips.data.permissions.PermissionsManager;

import org.xwiki.component.annotation.Component;
import org.phenotips.data.permissions.AccessLevel;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.users.User;
import org.phenotips.data.permissions.Owner;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

/**
 * Implementation that allows all access to the owner of a patient.
 *
 * @version $Id$
 * @since 1.0RC1
 */
@Component
@Named("owner-access")
@Singleton
public class OwnerAccessAuthorizationModule implements AuthorizationModule {
    /**
     * Checks to see if document is a patient (DocumentReference).
     */
    @Inject
    private PatientRepository patientRepository;

    /**
     * Checks to see if it has the permission to access the document or patient.
     */
    @Inject
    private PermissionsManager permissionsManager;

    @Inject
    private PatientAccessHelper pAHelper;

    @Inject
    private GroupManager groupManager;

    @Override
    public int getPriority() {
        return 400;
    }

    @Override
    public Boolean hasAccess(User user, Right access, EntityReference entity) {
        if (user == null || entity == null) {
            return null;
        }

        // This converts the document to a patient.
        Patient patient = this.patientRepository.get(entity.toString());
        if (patient == null) {
            return null;
        }

        PatientAccess patientAccess = this.permissionsManager.getPatientAccess(patient);
        Owner owner = patientAccess.getOwner();

        // If the target user is the owner or associated by a group, allow all access to patient.
        if (patientAccess.isOwner(user.getProfileDocument())) {
            return true;
        }
        else if(owner.isGroup()) {
            return true;
        }

        return null;
    }
}