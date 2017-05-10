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

import org.phenotips.data.Patient;
import org.phenotips.data.PatientRepository;
import org.phenotips.data.permissions.AccessLevel;
import org.phenotips.data.permissions.PatientAccess;
import org.phenotips.data.permissions.PermissionsManager;
import org.phenotips.data.permissions.Visibility;
import org.phenotips.security.authorization.AuthorizationModule;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.users.User;

import javax.inject.Inject;

public class VisibilityAccessAuthorizationModule implements AuthorizationModule {

    /** Checks to see if document is a patient (DocumentReference). */
    @Inject
    private PatientRepository patientRepository;

    /**
     * Checks to see if it has the permission to access the document or patient.
     */
    @Inject
    private PermissionsManager permissionsManager;

    @Override
    public int getPriority() {
        return 100;
    }

    @Override
    public Boolean hasAccess(User user, Right access, EntityReference entity) {
        if(user == null || access == null || entity == null) {
            return null;
        }

        // This converts the document to a patient.
        Patient patient = this.patientRepository.get(entity.toString());
        if (patient == null) {
            return null;
        }

        Visibility visibility = this.permissionsManager.getDefaultVisibility();

        // Checks if the visibility of Patient Record and the access rights
        if(visibility.getName().equals("open") && access.getName().equals("edit")) {
            return true;
        }
        else if (visibility.getName().equals("public") && access.getName().equals("view")) {
            return true;
        }
        return null;
    }
}
