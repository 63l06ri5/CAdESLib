using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using System.Linq;

namespace CAdESLib.Helpers
{
    public class OrderedAttributeTable
    {
        private Dictionary<DerObjectIdentifier, IList<Attribute>> attributesDict;
        private IList<Attribute> attributesList;
        public OrderedAttributeTable(Asn1Set? attributes = null)
        {
            InitFields();

            if (attributesList == null || attributesDict == null)
            {
                throw new System.ArgumentNullException();
            }

            if (attributes == null)
            {
                return;
            }

            foreach (var a in attributes)
            {
                var attr = Attribute.GetInstance(a);
                AddAttribute(attr);
            }
        }

        private void InitFields()
        {
            InitList();
            InitDict();
        }

        private void InitList()
        {
            this.attributesList = new List<Attribute>();
        }

        private void InitDict()
        {
            this.attributesDict = new Dictionary<DerObjectIdentifier, IList<Attribute>>();
        }


        public void AddAttribute(Attribute a)
        {
            AddAttributeToList(a);
            AddAttributeToDict(a);
        }

        private void AddAttributeToList(Attribute a)
        {
            this.attributesList.Add(a);
        }

        private void AddAttributeToDict(Attribute a)
        {
            DerObjectIdentifier oid = a.AttrType;
            var obj = this.attributesDict.GetValueOrDefault(oid);

            if (obj == null)
            {
                this.attributesDict[oid] = new List<Attribute>();
            }
            this.attributesDict[oid].Add(a);
        }

        public void RemoveAttribute(Attribute a)
        {
            attributesList.Remove(a);

            InitDict();
            foreach (var attr in attributesList)
            {
                AddAttributeToDict(attr);
            }
        }

        public void InsertAt(int index, Attribute a)
        {
            this.attributesList.Insert(index, a);
            AddAttributeToDict(a);
        }

        public int IndexOf(Attribute a)
        {
            return this.attributesList.IndexOf(a);
        }

        public void ReplaceAttribute(Attribute oldAttribute, DerSet attributeValue)
        {
            var index = this.IndexOf(oldAttribute);
            this.RemoveAttribute(oldAttribute);
            this.InsertAt(
                    index,
                    new Attribute(
                        oldAttribute.AttrType,
                        attributeValue));
        }

        public IList<Attribute>? this[DerObjectIdentifier oid]
        {
            get
            {
                return this.attributesDict.GetValueOrDefault(oid);
            }
        }

        public IList<Attribute> GetAll()
        {
            return this.attributesList.ToList();
        }

        public Asn1EncodableVector GetVector()
        {
            return Asn1EncodableVector.FromEnumerable(this.attributesList);
        }
    }
}
