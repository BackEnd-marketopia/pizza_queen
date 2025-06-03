<link rel="stylesheet" href="https://cdn.datatables.net/1.11.1/css/jquery.dataTables.min.css">

<table class="table table-hover table-borderless table-thead-bordered table-nowrap table-align-middle card-table w-100 mt-3" id="datatable">
    <thead class="thead-light">
        <tr>
            <th>{{translate('SL')}} </th>
            <th>{{translate('order')}}</th>
            <th>{{translate('date')}}</th>
            <th>{{translate('qty')}}</th>
            <th>{{translate('amount')}}</th>
        </tr>
    </thead>
    <tbody>
    @foreach($data as $key => $row)
        <tr>
            <td class="">
                {{$key + 1}}
            </td>
            <td class="">
                <a href="{{route('admin.orders.details', ['id' => $row['order_id']])}}">{{$row['order_id']}}</a>
            </td>
            <td>{{date('d M Y', strtotime($row['date']))}}</td>
            <td>{{$row['quantity']}}</td>
            <td>{{ \App\CentralLogics\Helpers::set_symbol($row['price']) }}</td>
        </tr>
    @endforeach
    </tbody>
</table>

<script type="text/javascript">
    $(document).ready(function () {
        $('input').addClass('form-control');
    });
    if (typeof window.calculated === 'undefined') {
            window.calculated = false;
        }
    var datatable = $.HSCore.components.HSDatatables.init($('#datatable'), {
        dom: 'Bfrtip',
        buttons: [
            {
                extend: 'copy',
                text: 'Copy',
                className: 'btn btn-sm btn-primary'
            },
            {
                extend: 'excel',
                text: 'Excel',
                className: 'btn btn-sm btn-primary',
                action: function (e, dt, button, config) {
                    if (!calculated) {
                    let totalQty = 0;
                    let totalAmount = 0;
                    dt.rows().every(function () {
                        let data = this.data();
                        totalQty += parseInt(data[3]);
                        totalAmount += parseFloat(data[4].replace(/[^\d.-]/g, ''));
                    });

                    dt.row.add([
                        '',
                        'Total',
                        '',
                        totalQty,
                        totalAmount.toFixed(2)
                    ]).draw(false);
                    window.calculated = true;
                }
                    $.fn.dataTable.ext.buttons.excelHtml5.action.call(this, e, dt, button, config);
                }
            },
            {
                extend: 'csv',
                text: 'CSV',
                className: 'btn btn-sm btn-primary'
            },
            {
                extend: 'print',
                text: 'Print',
                className: 'btn btn-sm btn-primary'
            }
        ],
        "iDisplayLength": 25,
    });
</script>
