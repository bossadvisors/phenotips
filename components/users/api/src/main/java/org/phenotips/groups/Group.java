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
package org.phenotips.groups;

import org.phenotips.Constants;

import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.stability.Unstable;

/**
 * A group of users.
 *
 * @version $Id$
 * @since 1.0M9
 */
@Unstable
public interface Group
{
    /** The XClass used for storing work groups. */
    EntityReference CLASS_REFERENCE = new EntityReference("PhenoTipsGroupClass", EntityType.DOCUMENT,
        Constants.CODE_SPACE_REFERENCE);

    /**
     * Get a reference to the XDocument where this group is defined.
     *
     * @return a valid document reference
     */
    DocumentReference getReference();
}
