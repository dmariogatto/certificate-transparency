﻿using System;

namespace Cats.CertificateTransparency.Attributes
{
    [AttributeUsage(AttributeTargets.All)]
    internal sealed class PreserveAttribute : Attribute
    {
        public bool AllMembers;
        public bool Conditional;

        public PreserveAttribute(bool allMembers, bool conditional)
        {
            AllMembers = allMembers;
            Conditional = conditional;
        }

        public PreserveAttribute()
        {
        }
    }
}
