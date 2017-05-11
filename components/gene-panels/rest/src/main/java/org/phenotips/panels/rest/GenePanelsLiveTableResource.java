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
package org.phenotips.panels.rest;

import org.phenotips.rest.ParentResource;
import org.phenotips.rest.Relation;

import org.xwiki.stability.Unstable;

import java.util.List;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.restlet.ext.jaxrs.internal.wrappers.RootResourceClass;

/**
 * A resource for integrating a gene panel display with a LiveTable.
 *
 * @version $Id$
 * @since 1.4
 */
@Unstable("New API introduced in 1.4")
@Path("/suggested-gene-panels/livetable")
@Relation("https://phenotips.org/rel/genePanels")
@ParentResource(RootResourceClass.class)
public interface GenePanelsLiveTableResource
{
    /**
     * Retrieves a JSON representation of genes associated with provided terms and counts for each gene. The following
     * request parameters are used:
     *
     * @param presentTerms a list of term IDs that are observed to be present (e.g. HP:0001154)
     * @param absentTerms a list of term IDs that are observed to be absent
     * @param offset the offset for the results, numbering starts from 1
     * @param limit the number of results to display, must be an integer
     * @param reqNo the request number, must be an integer
     *
     * @return associated genes and counts data if successful, an error code otherwise
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    Response getGeneCountsFromPhenotypes(
        @QueryParam("present-term") List<String> presentTerms,
        @QueryParam("absent-term") List<String> absentTerms,
        @QueryParam("offset") @DefaultValue("1") int offset,
        @QueryParam("limit") @DefaultValue("-1") int limit,
        @QueryParam("reqNo") @DefaultValue("0") int reqNo);
}
