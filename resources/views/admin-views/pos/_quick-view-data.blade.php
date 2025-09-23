<style>
    .modal-dialog-scrollable .modal-content {
        max-height: 90vh;
    }
    .modal-dialog-scrollable .modal-body {
        overflow-y: auto;
        max-height: calc(90vh - 120px);
    }
    .quick-view-modal-body {
        max-height: 70vh;
        overflow-y: auto;
    }
</style>

<div class="modal fade" id="free-product-modal" tabindex="-1" role="dialog" aria-labelledby="freeProductModalLabel"
    aria-hidden="true">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="freeProductModalLabel">{{translate('Available Products')}}</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <div class="row" id="free-products-container">
                    <div class="col-12 text-center">
                        <div class="spinner-border text-primary" role="status">
                            <span class="sr-only">{{translate('Loading...')}}</span>
                        </div>
                        <p class="mt-2">{{translate('Loading free products...')}}</p>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="dismiss" data-dismiss="modal">{{translate('Close')}}</button>
            </div>
        </div>
    </div>
</div>
<div class="modal-header p-2">
    <h4 class="modal-title product-title"></h4>
    <button class="close call-when-done" type="button" data-dismiss="modal" aria-label="Close">
        <span aria-hidden="true">&times;</span>
    </button>
</div>
<div class="modal-body quick-view-modal-body">
    <div class="d-flex flex-wrap gap-3">
        <div class="d-flex align-items-center justify-content-center active">
            <img class="img-responsive rounded" width="160"
                 src="{{$product['imageFullPath']}}"
                 data-zoom="{{$product['imageFullPath']}}"
                 alt="{{ translate('product') }}">
            <div class="cz-image-zoom-pane"></div>
        </div>

        <?php
$pb = json_decode($product->branch_products, true);
$discountData = [];
if (isset($pb[0])) {
    $price = $pb[0]['price'];
    $discountData = [
        'discount_type' => $pb[0]['discount_type'],
        'discount' => $pb[0]['discount']
    ];
} else {
    $price = $product['price'];
    $discountType = $product['discount_type'];
    $discount = $product['discount'];
    $discountData = [
        'discount_type' => $product['discount_type'],
        'discount' => $product['discount']
    ];
}
        ?>
        <div class="details">
            <div class="break-all">
                <a href="#" class="d-block h3 mb-2 product-title">{{ Str::limit($product->name, 100) }}</a>
            </div>

            <div class="mb-2 text-dark d-flex align-items-baseline gap-2">
                <h3 class="font-weight-normal text-accent mb-0">
                    {{Helpers::set_symbol(($price - Helpers::discount_calculate($discountData, $price))) }}
                </h3>
                @if($discountData['discount'] > 0)
                    <strike class="fz-12">
                        {{Helpers::set_symbol($price) }}
                    </strike>
                @endif
            </div>

            @if($discountData['discount'] > 0)
                <div class="mb-3 text-dark">
                    <strong>{{translate('Discount : ')}}</strong>
                    <strong
                        id="set-discount-amount">{{Helpers::set_symbol(\App\CentralLogics\Helpers::discount_calculate($discountData, $price)) }}</strong>
                </div>
            @endif
        </div>
    </div>
    <div class="row pt-2">
        <div class="col-12">
            <?php
$cart = false;
if (session()->has('cart')) {
    foreach (session()->get('cart') as $key => $cartItem) {
        if (is_array($cartItem) && $cartItem['id'] == $product['id']) {
            $cart = $cartItem;
        }
    }
}

            ?>
            <h3 class="mt-3">{{translate('description')}}</h3>
            <div class="d-block text-break text-dark __descripiton-txt __not-first-hidden">
                <div>
                    <p>
                        {!! $product->description !!}
                    </p>
                </div>
                <div class="show-more text-info text-center">
                    <span class="">See More</span>
                </div>
            </div>
            <form id="add-to-cart-form" class="mb-2">
                @csrf
                <input type="hidden" name="id" value="{{ $product->id }}">
                <input type="hidden" name="category_id" value="{{ $product->category_ids }}">
                <input type="hidden" name="is_free" value="false">
                <input type="hidden" name="free_for_product" value="">
                @if (isset($product->branch_products) && count($product->branch_products))
                    @foreach($product->branch_products as $branch_product)
                        @foreach ($branch_product->variations as $key => $choice)
                            @if (isset($choice->price) == false)
                                <div class="h3 p-0 pt-2">
                                    {{ $choice['name'] }}
                                    <small class="text-muted custom-text-size12">
                                        ({{ ($choice['required'] == 'on') ? translate('Required') : translate('optional') }})
                                    </small>
                                </div>
                                @if ($choice['min'] != 0 && $choice['max'] != 0)
                                    <small class="d-block mb-3">
                                        {{ translate('You_need_to_select_minimum_ ') }} {{ $choice['min'] }} {{ translate('to_maximum_ ') }} {{ $choice['max'] }} {{ translate('options') }}
                                    </small>
                                @endif

                                <div>
                                    <input type="hidden"  name="variations[{{ $key }}][min]" value="{{ $choice['min'] }}" >
                                    <input type="hidden"  name="variations[{{ $key }}][max]" value="{{ $choice['max'] }}" >
                                    <input type="hidden"  name="variations[{{ $key }}][required]" value="{{ $choice['required'] }}" >
                                    <input type="hidden" name="variations[{{ $key }}][name]" value="{{ $choice['name'] }}">
                                    @foreach ($choice['values'] as $k => $option)
                                        <div class="form-check form--check d-flex pr-5 mr-6">
                                            <input class="form-check-input" type="{{ ($choice['type'] == "multi") ? "checkbox" : "radio"}}" id="choice-option-{{ $key }}-{{ $k }}"
                                                   name="variations[{{ $key }}][values][label][]" value="{{ $option['label'] }}" autocomplete="off">

                                            <label class="form-check-label"
                                                   for="choice-option-{{ $key }}-{{ $k }}">{{ Str::limit($option['label'], 20, '...') }}</label>
                                            <span class="ml-auto">{{Helpers::set_symbol($option['optionPrice']) }}</span>
                                        </div>
                                    @endforeach
                                </div>

                            @endif
                        @endforeach
                    @endforeach

                @endif

                <div class="d-flex align-items-center justify-content-between mb-3 mt-4">
                    <h3 class="product-description-label mt-2 mb-0">{{translate('Quantity')}}:</h3>

                    <div class="product-quantity d-flex align-items-center">
                        <div class="product-quantity-group d-flex align-items-center">
                            <button class="btn btn-number text-dark p-2" type="button"
                                    data-type="minus" data-field="quantity"
                                    disabled="disabled">
                                    <i class="tio-remove font-weight-bold"></i>
                            </button>
                            <input type="text" name="quantity"
                                   class="form-control input-number text-center cart-qty-field"
                                   placeholder="1" value="1" min="1" max="100">
                            <button class="btn btn-number text-dark p-2" type="button" data-type="plus"
                                    data-field="quantity">
                                    <i class="tio-add font-weight-bold"></i>
                            </button>
                        </div>
                    </div>
                </div>
                @php($addOns = json_decode($product->add_ons))
                @if(count($addOns) > 0)
                    <h3 class="pt-2">{{ translate('addon') }}</h3>

                    <div class="d-flex flex-wrap addon-wrap">
                        @foreach (\App\Model\AddOn::whereIn('id', $addOns)->get() as $key => $add_on)
                            <div class="addon-item flex-column">
                                <input type="hidden" name="addon-price{{ $add_on->id }}" value="{{$add_on->price}}">
                                <input class="btn-check addon-chek" type="checkbox"
                                       id="addon{{ $key }}" onchange="addon_quantity_input_toggle(event)"
                                       name="addon_id[]" value="{{ $add_on->id }}"
                                       autocomplete="off">
                                <label class="d-flex align-items-center btn btn-sm check-label addon-input mb-0 h-100 break-all"
                                       for="addon{{ $key }}">{{ $add_on->name }} <br>
                                    {{ \App\CentralLogics\Helpers::set_symbol($add_on->price) }}
                                </label>
                                <label class="input-group addon-quantity-input shadow bg-white rounded mb-0 d-flex align-items-center"
                                       for="addon{{ $key }}">
                                    <button class="btn btn-sm h-100 text-dark px-0" type="button"
                                            onclick="this.parentNode.querySelector('input[type=number]').stepDown(), getVariantPrice()">
                                        <i class="tio-remove  font-weight-bold"></i></button>
                                    <input type="number" name="addon-quantity{{ $add_on->id }}"
                                           class="text-center border-0 h-100"
                                           placeholder="1" value="1" min="1" max="100" readonly>
                                    <button class="btn btn-sm h-100 text-dark px-0" type="button"
                                            onclick="this.parentNode.querySelector('input[type=number]').stepUp(), getVariantPrice()">
                                        <i class="tio-add  font-weight-bold"></i></button>
                                </label>
                            </div>
                        @endforeach
                    </div>
                @endif
                <div class="row no-gutters mt-4 text-dark" id="chosen_price_div">
                    <div class="col-2">
                        <div class="product-description-label">{{translate('Total_Price')}}:</div>
                    </div>
                    <div class="col-10">
                        <div class="product-price">
                            <strong id="chosen_price"></strong>
                        </div>
                    </div>
                </div>

                <div class="d-flex justify-content-center align-items-center gap-2 mt-2">
                    <button class="btn btn-primary px-md-5 add-to-cart-button" type="button">
                        <i class="tio-shopping-cart"></i>
                        {{translate('add')}}
                    </button>
                    @if ($product->has_free)
                        <button class="btn btn-secondary px-md-5" id="show-free-product" type="button">
                        <i class="tio-gift"></i>
                        {{translate('add free product')}}
                    </button>
                    @endif
                </div>

            </form>
        </div>
    </div>
</div>

<script>
    "use strict";

    cartQuantityInitialize();
    getVariantPrice();

    $('#add-to-cart-form input').on('change', function () {
        getVariantPrice();
    });

    $('.show-more span').on('click', function(){
        $('.__descripiton-txt').toggleClass('__not-first-hidden')
        if($(this).hasClass('active')) {
            $('.show-more span').text('{{translate('See More')}}')
            $(this).removeClass('active')
        }else {
            $('.show-more span').text('{{translate('See Less')}}')
            $(this).addClass('active')
        }
    })

    $('.addon-chek').change(function() {
        addon_quantity_input_toggle($(this));
    });

    $('.decrease-quantity').click(function() {
        var input = $(this).closest('.addon-quantity-input').find('.addon-quantity');
        input.val(parseInt(input.val()) - 1);
        getVariantPrice();
    });

    $('.increase-quantity').click(function() {
        var input = $(this).closest('.addon-quantity-input').find('.addon-quantity');
        input.val(parseInt(input.val()) + 1);
        getVariantPrice();
    });

    $('.add-to-cart-button').click(function() {
        addToCart();
    });
    $('#show-free-product').click(function() {
        showFreeProduct();
    });
    
    // Global variable to store current product for free products
    var currentProductForFree = null;
    
    function showFreeProduct(){
        var product_id = $('input[name="id"]').val();
        
        // Store the current product ID for later use
        currentProductForFree = product_id;

        // Show modal first with loading state
        $('#free-product-modal').modal('show');

         $.ajax({
            url: '{{ url('api/v1/can_free') }}/' + product_id,
            type: 'GET',
            success: function (response) {
                 console.log('API Response:', response);

                 let modalBody = $('#free-products-container');
                 modalBody.empty(); // Clear any existing content in the modal body

                 if (response.debug) {
                     console.log('Debug Info:', response.debug);
                 }

                 if (response.products && response.products.length > 0) {
                     console.log(`Found ${response.products.length} free products`);
                     // Loop through the products and generate HTML
                     response.products.forEach(product => {
                        product.price = 0;
                         const productHTML = `
                <div class="col-md-6 col-lg-4 mb-3">
                    <div class="card h-100 shadow-sm">
                        <div class="card-img-container" style="height: 200px; overflow: hidden;">
                            <img src="{{asset('storage/app/public/product/')}}/${product.image}" 
                                 class="card-img-top w-100 h-100" 
                                 style="object-fit: cover;"
                                 alt="${product.name}"
                                 onerror="this.src='{{asset('public/assets/admin/img/160x160/img2.jpg')}}'">
                        </div>
                        <div class="card-body d-flex flex-column">
                            <h6 class="card-title text-truncate">${product.name}</h6>
                            <p class="card-text text-muted small flex-grow-1">${product.description || '{{translate('No description available.')}}'}</p>
                            <div class="text-center mt-auto">
                                <button class="btn btn-primary btn-sm w-100" id="select-free-product" data-id="${product.id}" data-name="${product.name}">
                                    <i class="tio-eye"></i> {{translate('View & Add')}}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;

                         modalBody.append(productHTML); // Add product HTML to modal body
                     });
                 } else {
                     console.log('No free products found or empty array');
                     console.log('Response products:', response.products);
                     modalBody.html(`
                        <div class="col-12 text-center py-4">
                            <div class="mb-3">
                                <i class="tio-sentiment-dissatisfied" style="font-size: 3rem; color: #ccc;"></i>
                            </div>
                            <h5 class="text-muted">{{translate('No free products available')}}</h5>
                            <p class="text-muted">{{translate('There are no free products available for this item.')}}</p>
                            ${response.debug ? `<small class="text-muted">Debug: ${JSON.stringify(response.debug)}</small>` : ''}
                        </div>
                    `);
                 }
             },
             error: function (xhr, status, error) {
                console.error('AJAX Error:', error);
                console.error('Response:', xhr.responseText);
                
                try {
                    let response = JSON.parse(xhr.responseText);
                    if (response.message) {
                        // Show error message to user
                        toastr.error(response.message);
                        // Hide the modal since there's no free products
                        $('#free-product-modal').modal('hide');
                        return;
                    }
                } catch (e) {
                    console.error('Error parsing response:', e);
                }
                
                // Fallback error handling
                let modalBody = $('#free-products-container');
                modalBody.html(`
                    <div class="col-12 text-center py-4">
                        <div class="mb-3">
                            <i class="tio-error" style="font-size: 3rem; color: #dc3545;"></i>
                        </div>
                        <h5 class="text-danger">{{translate('Error loading products')}}</h5>
                        <p class="text-muted">{{translate('Please try again later.')}}</p>
                        <small class="text-muted">Error: ${error}</small>
                    </div>
                `);
            }
        });
    }
    $('#dismiss').click(function(){
        $('#free-product-modal').modal('hide');
    })

</script>

