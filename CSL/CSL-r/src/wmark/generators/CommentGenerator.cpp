﻿/*
** Xin YUAN, 2019, BSD (2)
*/

////////////////////////////////////////////////////////////////////////////////

#include "precomp.h"

#include "../WmarkHtmlGenerator.h"

////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
namespace CSL {
////////////////////////////////////////////////////////////////////////////////

// WmarkHtmlGeneratorHelper

WmarkMetaDataTraversalAction WmarkHtmlGeneratorHelper::get_CommentGenerator()
{
	return [](bool bOpen, RdMetaData& data, RdMetaDataPosition pos, std::ostream& stm)->bool
			{
				stm << "<!-- comment -->" << "\r\n";
				return true;
			};
}

////////////////////////////////////////////////////////////////////////////////
}
////////////////////////////////////////////////////////////////////////////////
