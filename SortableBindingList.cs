using System.ComponentModel;
using System.Net;
using System.Reflection;

namespace EthernetTools;

/// <summary>
/// BindingList&lt;T&gt; that supports column sorting in DataGridView by
/// implementing the sort hooks. Sorts the underlying list in place.
/// </summary>
public sealed class SortableBindingList<T> : BindingList<T>
{
    private bool _sorted;
    private ListSortDirection _direction = ListSortDirection.Ascending;
    private PropertyDescriptor? _sortProperty;

    protected override bool SupportsSortingCore => true;
    protected override bool IsSortedCore => _sorted;
    protected override ListSortDirection SortDirectionCore => _direction;
    protected override PropertyDescriptor? SortPropertyCore => _sortProperty;

    protected override void ApplySortCore(PropertyDescriptor prop, ListSortDirection direction)
    {
        _sortProperty = prop;
        _direction = direction;

        var items = (List<T>)Items;
        var pi = typeof(T).GetProperty(prop.Name,
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
        if (pi is null) return;

        items.Sort((a, b) =>
        {
            var va = a is null ? null : pi.GetValue(a);
            var vb = b is null ? null : pi.GetValue(b);
            int cmp;
            if (va is null && vb is null) cmp = 0;
            else if (va is null) cmp = -1;
            else if (vb is null) cmp = 1;
            else if (va is IPAddress ipa && vb is IPAddress ipb) cmp = IpToUint(ipa).CompareTo(IpToUint(ipb));
            else if (va is IComparable cmpA) cmp = cmpA.CompareTo(vb);
            else cmp = string.Compare(va.ToString(), vb.ToString(), StringComparison.OrdinalIgnoreCase);
            return direction == ListSortDirection.Ascending ? cmp : -cmp;
        });

        _sorted = true;
        OnListChanged(new ListChangedEventArgs(ListChangedType.Reset, -1));
    }

    private static uint IpToUint(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return 0;
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    protected override void RemoveSortCore()
    {
        _sorted = false;
        _sortProperty = null;
        OnListChanged(new ListChangedEventArgs(ListChangedType.Reset, -1));
    }
}
