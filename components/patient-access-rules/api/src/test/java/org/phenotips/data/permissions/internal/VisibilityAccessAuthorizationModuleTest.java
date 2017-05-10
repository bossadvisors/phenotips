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

import org.apache.xmlbeans.impl.xb.xsdschema.Public;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.phenotips.data.Patient;
import org.phenotips.data.PatientRepository;
import org.phenotips.data.permissions.AccessLevel;
import org.phenotips.data.permissions.PatientAccess;
import org.phenotips.data.permissions.PermissionsManager;
import org.phenotips.data.permissions.internal.visibility.OpenVisibility;
import org.phenotips.data.permissions.internal.visibility.PublicVisibility;
import org.phenotips.security.authorization.AuthorizationModule;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.test.mockito.MockitoComponentMockingRule;
import org.xwiki.users.User;
import org.phenotips.data.permissions.Visibility;

import static org.mockito.Mockito.when;

public class VisibilityAccessAuthorizationModuleTest {
    @Rule
    public final MockitoComponentMockingRule<AuthorizationModule> mocker =
            new MockitoComponentMockingRule<AuthorizationModule>(VisibilityAccessAuthorizationModule.class);

    @Mock
    private User user;

    @Mock
    private Right right;

    @Mock
    private Patient patient;

    @Mock
    private PatientAccess pAccess;

    private DocumentReference doc = new DocumentReference("xwiki", "data", "P01");

    @Mock
    private DocumentReference userProfile;

    @Mock
    private AccessLevel grantedAccess;

    @Mock
    private AccessLevel requestedAccess;

    @Mock
    private OpenVisibility open;

    @Mock
    private PublicVisibility publicVis;

    @Mock
    private Visibility visibility;

    @Before
    public void setupMocks()
    {
        MockitoAnnotations.initMocks(this);
        when(this.user.getProfileDocument()).thenReturn(this.userProfile);
    }

    @Test
    public void openEditVisibilityTest() throws ComponentLookupException {
        PatientRepository repo = this.mocker.getInstance(PatientRepository.class);
        when(repo.get("xwiki:data.P01")).thenReturn(this.patient);
        PermissionsManager pm = this.mocker.getInstance(PermissionsManager.class);
        when(pm.getPatientAccess(this.patient)).thenReturn(this.pAccess);
        when(pm.getDefaultVisibility()).thenReturn(this.open);
        when(pm.getDefaultVisibility().getName()).thenReturn("open");
        when(this.pAccess.getAccessLevel(this.userProfile)).thenReturn(this.grantedAccess);

        when(this.visibility.getName()).thenReturn("open");
        when(pm.resolveVisibility("open")).thenReturn(this.visibility);
        when(this.right.getName()).thenReturn("edit");
        when(pm.resolveAccessLevel("edit")).thenReturn(this.requestedAccess);

        when(this.visibility.compareTo(this.open)).thenReturn(0);
        when(this.grantedAccess.compareTo(this.requestedAccess)).thenReturn(0);
        Assert.assertTrue(this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, this.doc));
    }

    @Test
    public void publicViewVisibilityTest() throws ComponentLookupException {
        PatientRepository repo = this.mocker.getInstance(PatientRepository.class);
        when(repo.get("xwiki:data.P01")).thenReturn(this.patient);
        PermissionsManager pm = this.mocker.getInstance(PermissionsManager.class);
        when(pm.getPatientAccess(this.patient)).thenReturn(this.pAccess);
        when(pm.getDefaultVisibility()).thenReturn(this.publicVis);
        when(pm.getDefaultVisibility().getName()).thenReturn("public");
        when(this.pAccess.getAccessLevel(this.userProfile)).thenReturn(this.grantedAccess);

        when(this.visibility.getName()).thenReturn("public");
        when(pm.resolveVisibility("public")).thenReturn(this.visibility);
        when(this.right.getName()).thenReturn("view");
        when(pm.resolveAccessLevel("view")).thenReturn(this.requestedAccess);

        when(this.visibility.compareTo(this.publicVis)).thenReturn(0);
        when(this.grantedAccess.compareTo(this.requestedAccess)).thenReturn(0);
        Assert.assertTrue(this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, this.doc));
    }

    @Test
    public void incorrectPermissionsTest() throws ComponentLookupException {
        PatientRepository repo = this.mocker.getInstance(PatientRepository.class);
        when(repo.get("xwiki:data.P01")).thenReturn(this.patient);
        PermissionsManager pm = this.mocker.getInstance(PermissionsManager.class);
        when(pm.getPatientAccess(this.patient)).thenReturn(this.pAccess);
        when(pm.getDefaultVisibility()).thenReturn(this.publicVis);
        when(pm.getDefaultVisibility().getName()).thenReturn("hidden");
        when(this.pAccess.getAccessLevel(this.userProfile)).thenReturn(this.grantedAccess);

        when(this.visibility.getName()).thenReturn("hidden");
        when(pm.resolveVisibility("hidden")).thenReturn(this.visibility);
        when(this.right.getName()).thenReturn("none");
        when(pm.resolveAccessLevel("none")).thenReturn(this.requestedAccess);

        when(this.visibility.compareTo(this.publicVis)).thenReturn(0);
        when(this.grantedAccess.compareTo(this.requestedAccess)).thenReturn(0);
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, this.doc));

    }

    @Test
    public void noActionWithUnknownRight() throws ComponentLookupException
    {
        PatientRepository repo = this.mocker.getInstance(PatientRepository.class);
        when(repo.get("xwiki:data.P01")).thenReturn(this.patient);
        PermissionsManager pm = this.mocker.getInstance(PermissionsManager.class);
        when(pm.getPatientAccess(this.patient)).thenReturn(this.pAccess);
        when(pm.getDefaultVisibility()).thenReturn(this.publicVis);
        when(pm.getDefaultVisibility().getName()).thenReturn("hidden");
        when(this.pAccess.getAccessLevel(this.userProfile)).thenReturn(this.grantedAccess);

        when(this.visibility.getName()).thenReturn("hidden");
        when(pm.resolveVisibility("hidden")).thenReturn(this.visibility);
        when(this.right.getName()).thenReturn("manage");
        when(pm.resolveAccessLevel("manage")).thenReturn(null);
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, this.doc));
    }

    @Test
    public void noActionWithNonPatient() throws ComponentLookupException
    {
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, this.doc));
    }

    @Test
    public void noActionWithNullArguments() throws ComponentLookupException
    {
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(null, this.right, this.doc));
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, null));
    }

    @Test
    public void expectedPriority() throws ComponentLookupException
    {
        Assert.assertEquals(100, this.mocker.getComponentUnderTest().getPriority());
    }

}