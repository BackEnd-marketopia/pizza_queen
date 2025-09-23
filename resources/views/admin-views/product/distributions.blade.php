@extends('layouts.admin.app')

@section('title', translate('Product Distribution Management'))

@section('content')
<div class="content container-fluid">
    <!-- Page Header -->
    <div class="page-header">
        <div class="row align-items-center">
            <div class="col-sm mb-2 mb-sm-0">
                <h1 class="page-header-title">
                    <i class="tio-share"></i> {{ translate('Product Distribution Management') }}
                </h1>
            </div>
            <div class="col-sm-auto">
                <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#applyToAllModal">
                    <i class="tio-add"></i> {{ translate('Apply to All Products') }}
                </button>
            </div>
        </div>
    </div>

    <!-- Stats Cards -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card">
                <div class="card-body text-center">
                    <h4 class="text-primary">{{ $products->total() }}</h4>
                    <p class="text-muted mb-0">{{ translate('Total Products') }}</p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card">
                <div class="card-body text-center">
                    <h4 class="text-success">{{ $branches->count() }}</h4>
                    <p class="text-muted mb-0">{{ translate('Active Branches') }}</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Products Table -->
    <div class="card">
        <div class="card-header">
            <h5 class="card-title">{{ translate('Product Distribution Settings') }}</h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead class="thead-light">
                        <tr>
                            <th>{{ translate('Product') }}</th>
                            <th>{{ translate('Category') }}</th>
                            <th>{{ translate('Current Distribution') }}</th>
                            <th>{{ translate('Available Branches') }}</th>
                            <th>{{ translate('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($products as $product)
                        <tr>
                            <td>
                                <div class="d-flex align-items-center">
                                    <img src="{{ $product->imageFullPath }}" alt="{{ $product->name }}"
                                         class="avatar avatar-sm mr-3">
                                    <div>
                                        <h6 class="mb-0">{{ Str::limit($product->name, 30) }}</h6>
                                        <small class="text-muted">{{ translate('ID') }}: {{ $product->id }}</small>
                                    </div>
                                </div>
                            </td>
                            <td>
                                @php
                                    $category = json_decode($product->category_ids, true);
                                    $categoryName = '';
                                    if($category && isset($category[0]['id'])) {
                                        $cat = \App\Model\Category::find($category[0]['id']);
                                        $categoryName = $cat ? $cat->name : 'N/A';
                                    }
                                @endphp
                                {{ $categoryName }}
                            </td>
                            <td>
                                @php
                                    $distribution = $product->distribution;
                                    $type = $distribution ? $distribution->distribution_type : 'all_branches';
                                    $badgeClass = match($type) {
                                        'all_branches' => 'success',
                                        'selected_branches' => 'info',
                                        'main_only' => 'warning',
                                        default => 'secondary'
                                    };
                                    $typeText = match($type) {
                                        'all_branches' => translate('All Branches'),
                                        'selected_branches' => translate('Selected Branches'),
                                        'main_only' => translate('Main Branch Only'),
                                        default => translate('Not Set')
                                    };
                                @endphp
                                <span class="badge badge-{{ $badgeClass }}">{{ $typeText }}</span>
                            </td>
                            <td>
                                @if($distribution && $distribution->distribution_type === 'selected_branches')
                                    @php
                                        $selectedBranches = $distribution->branch_ids ?? [];
                                        $branchNames = [];
                                        foreach($selectedBranches as $branchId) {
                                            $branch = $branches->find($branchId);
                                            if($branch) {
                                                $branchNames[] = $branch->name;
                                            }
                                        }
                                    @endphp
                                    {{ implode(', ', $branchNames) }}
                                @elseif($distribution && $distribution->distribution_type === 'main_only')
                                    {{ translate('Main Branch Only') }}
                                @else
                                    {{ translate('All Branches') }}
                                @endif
                            </td>
                            <td>
                                <button type="button" class="btn btn-sm btn-outline-primary"
                                        onclick="editDistribution({{ $product->id }})">
                                    <i class="tio-edit"></i> {{ translate('Edit') }}
                                </button>
                            </td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div class="d-flex justify-content-center mt-4">
                {{ $products->links() }}
            </div>
        </div>
    </div>
</div>

<!-- Edit Distribution Modal -->
<div class="modal fade" id="editDistributionModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">{{ translate('Edit Product Distribution') }}</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <form id="distributionForm">
                @csrf
                <div class="modal-body">
                    <input type="hidden" id="product_id" name="product_id">

                    <div class="form-group">
                        <label>{{ translate('Distribution Type') }}</label>
                        <select name="distribution_type" id="distribution_type" class="form-control" onchange="if(typeof toggleBranchSelection === 'function') toggleBranchSelection()">
                            <option value="all_branches">{{ translate('All Branches') }}</option>
                            <option value="selected_branches">{{ translate('Selected Branches') }}</option>
                            <option value="main_only">{{ translate('Main Branch Only') }}</option>
                        </select>
                    </div>

                    <div class="form-group" id="branchSelection" style="display: none;">
                        <label>{{ translate('Select Branches') }}</label>
                        <div class="border p-3" style="max-height: 200px; overflow-y: auto;">
                            @foreach($branches as $branch)
                            <div class="form-check">
                                <input class="form-check-input branch-checkbox" type="checkbox"
                                       name="branch_ids[]" value="{{ $branch->id }}" id="branch_{{ $branch->id }}">
                                <label class="form-check-label" for="branch_{{ $branch->id }}">
                                    {{ $branch->name }}
                                </label>
                            </div>
                            @endforeach
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">{{ translate('Cancel') }}</button>
                    <button type="submit" class="btn btn-primary">{{ translate('Save Changes') }}</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Apply to All Modal -->
<div class="modal fade" id="applyToAllModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">{{ translate('Apply Distribution to All Products') }}</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <form id="applyToAllForm">
                @csrf
                <div class="modal-body">
                    <div class="alert alert-warning">
                        <i class="tio-warning"></i> {{ translate('This will update the distribution settings for all products. This action cannot be undone.') }}
                    </div>

                    <div class="form-group">
                        <label>{{ translate('Distribution Type') }}</label>
                        <select name="distribution_type" id="apply_distribution_type" class="form-control" onchange="if(typeof toggleApplyBranchSelection === 'function') toggleApplyBranchSelection()">
                            <option value="all_branches">{{ translate('All Branches') }}</option>
                            <option value="selected_branches">{{ translate('Selected Branches') }}</option>
                            <option value="main_only">{{ translate('Main Branch Only') }}</option>
                        </select>
                    </div>

                    <div class="form-group" id="applyBranchSelection" style="display: none;">
                        <label>{{ translate('Select Branches') }}</label>
                        <div class="border p-3" style="max-height: 200px; overflow-y: auto;">
                            @foreach($branches as $branch)
                            <div class="form-check">
                                <input class="form-check-input apply-branch-checkbox" type="checkbox"
                                       name="branch_ids[]" value="{{ $branch->id }}" id="apply_branch_{{ $branch->id }}">
                                <label class="form-check-label" for="apply_branch_{{ $branch->id }}">
                                    {{ $branch->name }}
                                </label>
                            </div>
                            @endforeach
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">{{ translate('Cancel') }}</button>
                    <button type="submit" class="btn btn-danger">{{ translate('Apply to All') }}</button>
                </div>
            </form>
        </div>
    </div>
</div>

@endsection

@section('script')
<script>
// Global functions
function editDistribution(productId) {
    // Get current distribution settings
    $.get('{{ url("admin/product-distribution/show") }}/' + productId)
        .done(function(response) {
            $('#product_id').val(productId);
            $('#distribution_type').val(response.distribution ? response.distribution.distribution_type : 'all_branches');

            // Reset checkboxes
            $('.branch-checkbox').prop('checked', false);

            if (response.distribution && response.distribution.distribution_type === 'selected_branches') {
                const branchIds = response.distribution.branch_ids || [];
                branchIds.forEach(function(branchId) {
                    $('#branch_' + branchId).prop('checked', true);
                });
            }

            toggleBranchSelection();
            $('#editDistributionModal').modal('show');
        });
}

function toggleBranchSelection() {
    const type = $('#distribution_type').val();
    if (type === 'selected_branches') {
        $('#branchSelection').show();
    } else {
        $('#branchSelection').hide();
    }
}

function toggleApplyBranchSelection() {
    const type = $('#apply_distribution_type').val();
    if (type === 'selected_branches') {
        $('#applyBranchSelection').show();
    } else {
        $('#applyBranchSelection').hide();
    }
}

$(document).ready(function() {
    // Handle form submission
    $('#distributionForm').on('submit', function(e) {
        e.preventDefault();

        const formData = new FormData(this);
        formData.append('_token', '{{ csrf_token() }}');

        $.ajax({
            url: '{{ route("admin.product.distribution.update") }}',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    toastr.success(response.message);
                    $('#editDistributionModal').modal('hide');
                    location.reload();
                } else {
                    toastr.error(response.message);
                }
            },
            error: function() {
                toastr.error('{{ translate("An error occurred") }}');
            }
        });
    });

    // Handle apply to all form
    $('#applyToAllForm').on('submit', function(e) {
        e.preventDefault();

        if (!confirm('{{ translate("Are you sure you want to apply this distribution to all products?") }}')) {
            return;
        }

        const formData = new FormData(this);
        formData.append('_token', '{{ csrf_token() }}');

        $.ajax({
            url: '{{ route("admin.product.distribution.apply-to-all") }}',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    toastr.success(response.message);
                    $('#applyToAllModal').modal('hide');
                    location.reload();
                } else {
                    toastr.error(response.message);
                }
            },
            error: function() {
                toastr.error('{{ translate("An error occurred") }}');
            }
        });
    });
});
</script>
@endsection