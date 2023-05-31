<xsl:stylesheet version = '1.0'
     xmlns:xsl='http://www.w3.org/1999/XSL/Transform'
     xmlns:vbox="http://www.virtualbox.org/">

<!--
    constants-python.xsl:
        XSLT stylesheet that generates VirtualBox_constants.py from
        VirtualBox.xidl.
-->
<!--
    Copyright (C) 2009-2023 Oracle and/or its affiliates.

    This file is part of VirtualBox base platform packages, as
    available from https://www.virtualbox.org.

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation, in version 3 of the
    License.

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, see <https://www.gnu.org/licenses>.

    SPDX-License-Identifier: GPL-3.0-only
-->

<xsl:output
  method="text"
  version="1.0"
  encoding="utf-8"
  indent="no"/>

<xsl:param name="g_sErrHFile"/>

<xsl:template match="/">
<xsl:text># -*- coding: utf-8 -*-

"""
VirtualBox COM/XPCOM constants.

This file is autogenerated from VirtualBox.xidl, DO NOT EDIT!
"""

__copyright__ = \
"""
Copyright (C) 2009-2023 Oracle and/or its affiliates.

This file is part of VirtualBox base platform packages, as
available from https://www.virtualbox.org.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, in version 3 of the
License.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see &lt;https://www.gnu.org/licenses&gt;.

SPDX-License-Identifier: GPL-3.0-only
"""

__version__ = "$Revision: 98108 $";



class VirtualBoxReflectionInfo:
    """
    Enum constants for the various python styles.
    """

    def __init__(self, fIsSym):
        self.__fIsSym = fIsSym

    # iprt/err.h + VBox/err.h constants:
    __dVBoxStatuses = {</xsl:text>
    <xsl:value-of select="document($g_sErrHFile)"/>

    <xsl:text disable-output-escaping="yes"><![CDATA[
    }

    __dValues = {]]></xsl:text>
    <xsl:for-each select="//enum">
        <xsl:text>
        '</xsl:text> <xsl:value-of select="@name"/><xsl:text>': {</xsl:text>
        <xsl:for-each select="const">
            <xsl:text>
            '</xsl:text>
            <xsl:value-of select="@name"/><xsl:text>': </xsl:text>
            <xsl:value-of select="@value"/><xsl:text>,</xsl:text>
        </xsl:for-each>
        <xsl:text>
        },</xsl:text>
    </xsl:for-each>
    <!-- VBox status codes: -->
    <xsl:text disable-output-escaping="yes"><![CDATA[
        # iprt/err.h + VBox/err.h constants:
        'VBoxStatus': __dVBoxStatuses,
    }

    __dValuesSym = {]]></xsl:text>
    <xsl:for-each select="//enum">
        <xsl:text>
        '</xsl:text> <xsl:value-of select="@name"/> <xsl:text>': {</xsl:text>
        <xsl:for-each select="const">
            <xsl:text>
            '</xsl:text> <xsl:value-of select="@name"/> <xsl:text>': '</xsl:text>
            <xsl:value-of select="@name"/>
            <xsl:text>',</xsl:text>
        </xsl:for-each>
        <xsl:text>
        },</xsl:text>
    </xsl:for-each>
    <!-- hack alert: force new output element to avoid large reallocations. -->
    <xsl:text disable-output-escaping="yes"><![CDATA[
    }

    __dValuesFlat = dict({]]></xsl:text>
    <xsl:for-each select="//enum">
        <xsl:variable name="ename">
            <xsl:value-of select="@name"/>
        </xsl:variable>
        <xsl:for-each select="const">
            <xsl:text>
        '</xsl:text> <xsl:value-of select="$ename"/> <xsl:text>_</xsl:text>
            <xsl:value-of select="@name"/> <xsl:text>': </xsl:text>
            <xsl:value-of select="@value"/><xsl:text>,</xsl:text>
        </xsl:for-each>
    </xsl:for-each>
    <!-- hack alert: force new output element to avoid large reallocations. -->
    <xsl:text disable-output-escaping="yes"><![CDATA[
        # Result constants:]]></xsl:text>
    <xsl:for-each select="//result[@value]">
        <xsl:text>
        '</xsl:text> <xsl:value-of select="@name"/> <xsl:text>': </xsl:text>
        <xsl:value-of select="@value"/><xsl:text>,</xsl:text>
    </xsl:for-each>

    <!-- hack alert: force new output element to avoid large reallocations. -->
    <xsl:text>
    }, **__dVBoxStatuses)

    __dValuesFlatSym = {</xsl:text>
    <xsl:for-each select="//enum">
        <xsl:variable name="ename">
            <xsl:value-of select="@name"/>
        </xsl:variable>
        <xsl:for-each select="const">
            <xsl:variable name="eval">
                <xsl:value-of select="concat($ename, '_', @name)"/>
            </xsl:variable>
            <xsl:text>
        '</xsl:text> <xsl:value-of select="$eval"/> <xsl:text>': </xsl:text>
            <xsl:text>'</xsl:text> <xsl:value-of select="@name"/> <xsl:text>',</xsl:text>
        </xsl:for-each>
    </xsl:for-each>
    <xsl:text>
        # Result constants:</xsl:text>
    <xsl:for-each select="//result[@value]">
        <xsl:text>
        '</xsl:text> <xsl:value-of select="@name"/> <xsl:text>': </xsl:text>
        <xsl:text>'</xsl:text><xsl:value-of select="@name"/><xsl:text>',</xsl:text>
    </xsl:for-each>
    <xsl:text>
    }

    def __getattr__(self, sAttrName):
        if self.__fIsSym:
            oValue = self.__dValuesFlatSym.get(sAttrName)
        else:
            oValue = self.__dValuesFlat.get(sAttrName)
        if oValue is None:
            raise AttributeError
        return oValue

    def all_values(self, sEnumName):
        """ Returns a dictionary with all the value names for a given enum type. """
        if self.__fIsSym:
            dValues = self.__dValuesSym.get(sEnumName)
        else:
            dValues = self.__dValues.get(sEnumName)
        if dValues is None:
            dValues = {}
        return dValues

</xsl:text>
</xsl:template>
</xsl:stylesheet>
